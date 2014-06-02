/*
 * DMA helper functions
 *
 * Copyright (c) 2009 Red Hat
 *
 * This work is licensed under the terms of the GNU General Public License
 * (GNU GPL), version 2 or later.
 */

#include "sysemu/dma.h"
#include "trace.h"
#include "qemu/range.h"
#include "qemu/thread.h"
#include "qemu/main-loop.h"

/* #define DEBUG_IOMMU */

int dma_memory_set(AddressSpace *as, dma_addr_t addr, uint8_t c, dma_addr_t len)
{
    dma_barrier(as, DMA_DIRECTION_FROM_DEVICE);

#define FILLBUF_SIZE 512
    uint8_t fillbuf[FILLBUF_SIZE];
    int l;
    bool error = false;

    memset(fillbuf, c, FILLBUF_SIZE);
    while (len > 0) {
        l = len < FILLBUF_SIZE ? len : FILLBUF_SIZE;
        error |= address_space_rw(as, addr, fillbuf, l, true);
        len -= l;
        addr += l;
    }

    return error;
}

void qemu_sglist_init(QEMUSGList *qsg, DeviceState *dev, int alloc_hint,
                      AddressSpace *as)
{
    qsg->sg = g_malloc(alloc_hint * sizeof(ScatterGatherEntry));
    qsg->nsg = 0;
    qsg->nalloc = alloc_hint;
    qsg->size = 0;
    qsg->as = as;
    qsg->dev = dev;
    object_ref(OBJECT(dev));
}

void qemu_sglist_add(QEMUSGList *qsg, dma_addr_t base, dma_addr_t len)
{
    if (qsg->nsg == qsg->nalloc) {
        qsg->nalloc = 2 * qsg->nalloc + 1;
        qsg->sg = g_realloc(qsg->sg, qsg->nalloc * sizeof(ScatterGatherEntry));
    }
    qsg->sg[qsg->nsg].base = base;
    qsg->sg[qsg->nsg].len = len;
    qsg->size += len;
    ++qsg->nsg;
}

void qemu_sglist_destroy(QEMUSGList *qsg)
{
    object_unref(OBJECT(qsg->dev));
    g_free(qsg->sg);
    memset(qsg, 0, sizeof(*qsg));
}

typedef struct {
    BlockDriverAIOCB common;
    BlockDriverState *bs;
    BlockDriverAIOCB *acb;
    QEMUSGList *sg;
    uint64_t sector_num;
    DMADirection dir;
    bool in_cancel;
    int sg_cur_index;
    dma_addr_t sg_cur_byte;
    QEMUIOVector iov;
    QEMUBH *bh;
    DMAIOFunc *io_func;
} DMAAIOCB;

static void dma_bdrv_cb(void *opaque, int ret);

static void reschedule_dma(void *opaque)
{
    DMAAIOCB *dbs = (DMAAIOCB *)opaque;

    qemu_bh_delete(dbs->bh);
    dbs->bh = NULL;
    dma_bdrv_cb(dbs, 0);
}

static void continue_after_map_failure(void *opaque)
{
    DMAAIOCB *dbs = (DMAAIOCB *)opaque;

    dbs->bh = qemu_bh_new(reschedule_dma, dbs);
    qemu_bh_schedule(dbs->bh);
}

static void dma_bdrv_unmap(DMAAIOCB *dbs)
{
    int i;

    for (i = 0; i < dbs->iov.niov; ++i) {
        dma_memory_unmap(dbs->sg->as, dbs->iov.iov[i].iov_base,
                         dbs->iov.iov[i].iov_len, dbs->dir,
                         dbs->iov.iov[i].iov_len);
    }
    qemu_iovec_reset(&dbs->iov);
}

static void dma_complete(DMAAIOCB *dbs, int ret)
{
    trace_dma_complete(dbs, ret, dbs->common.cb);

    dma_bdrv_unmap(dbs);
    if (dbs->common.cb) {
        dbs->common.cb(dbs->common.opaque, ret);
    }
    qemu_iovec_destroy(&dbs->iov);
    if (dbs->bh) {
        qemu_bh_delete(dbs->bh);
        dbs->bh = NULL;
    }
    if (!dbs->in_cancel) {
        /* Requests may complete while dma_aio_cancel is in progress.  In
         * this case, the AIOCB should not be released because it is still
         * referenced by dma_aio_cancel.  */
        qemu_aio_release(dbs);
    }
}

static void dma_bdrv_cb(void *opaque, int ret)
{
    DMAAIOCB *dbs = (DMAAIOCB *)opaque;
    dma_addr_t cur_addr, cur_len;
    void *mem;

    trace_dma_bdrv_cb(dbs, ret);

    dbs->acb = NULL;
    dbs->sector_num += dbs->iov.size / 512;

    if (dbs->sg_cur_index == dbs->sg->nsg || ret < 0) {
        dma_complete(dbs, ret);
        return;
    }
    dma_bdrv_unmap(dbs);

    while (dbs->sg_cur_index < dbs->sg->nsg) {
        cur_addr = dbs->sg->sg[dbs->sg_cur_index].base + dbs->sg_cur_byte;
        cur_len = dbs->sg->sg[dbs->sg_cur_index].len - dbs->sg_cur_byte;
        mem = dma_memory_map(dbs->sg->as, cur_addr, &cur_len, dbs->dir);
        if (!mem)
            break;
        qemu_iovec_add(&dbs->iov, mem, cur_len);
        dbs->sg_cur_byte += cur_len;
        if (dbs->sg_cur_byte == dbs->sg->sg[dbs->sg_cur_index].len) {
            dbs->sg_cur_byte = 0;
            ++dbs->sg_cur_index;
        }
    }

    if (dbs->iov.size == 0) {
        trace_dma_map_wait(dbs);
        cpu_register_map_client(dbs, continue_after_map_failure);
        return;
    }

    dbs->acb = dbs->io_func(dbs->bs, dbs->sector_num, &dbs->iov,
                            dbs->iov.size / 512, dma_bdrv_cb, dbs);
    assert(dbs->acb);
}

static void dma_aio_cancel(BlockDriverAIOCB *acb)
{
    DMAAIOCB *dbs = container_of(acb, DMAAIOCB, common);

    trace_dma_aio_cancel(dbs);

    if (dbs->acb) {
        BlockDriverAIOCB *acb = dbs->acb;
        dbs->acb = NULL;
        dbs->in_cancel = true;
        bdrv_aio_cancel(acb);
        dbs->in_cancel = false;
    }
    dbs->common.cb = NULL;
    dma_complete(dbs, 0);
}

static const AIOCBInfo dma_aiocb_info = {
    .aiocb_size         = sizeof(DMAAIOCB),
    .cancel             = dma_aio_cancel,
};

BlockDriverAIOCB *dma_bdrv_io(
    BlockDriverState *bs, QEMUSGList *sg, uint64_t sector_num,
    DMAIOFunc *io_func, BlockDriverCompletionFunc *cb,
    void *opaque, DMADirection dir)
{
    DMAAIOCB *dbs = qemu_aio_get(&dma_aiocb_info, bs, cb, opaque);

    trace_dma_bdrv_io(dbs, bs, sector_num, (dir == DMA_DIRECTION_TO_DEVICE));

    dbs->acb = NULL;
    dbs->bs = bs;
    dbs->sg = sg;
    dbs->sector_num = sector_num;
    dbs->sg_cur_index = 0;
    dbs->sg_cur_byte = 0;
    dbs->dir = dir;
    dbs->in_cancel = false;
    dbs->io_func = io_func;
    dbs->bh = NULL;
    qemu_iovec_init(&dbs->iov, sg->nsg);
    dma_bdrv_cb(dbs, 0);
    return &dbs->common;
}


BlockDriverAIOCB *dma_bdrv_read(BlockDriverState *bs,
                                QEMUSGList *sg, uint64_t sector,
                                void (*cb)(void *opaque, int ret), void *opaque)
{
    return dma_bdrv_io(bs, sg, sector, bdrv_aio_readv, cb, opaque,
                       DMA_DIRECTION_FROM_DEVICE);
}

BlockDriverAIOCB *dma_bdrv_write(BlockDriverState *bs,
                                 QEMUSGList *sg, uint64_t sector,
                                 void (*cb)(void *opaque, int ret), void *opaque)
{
    return dma_bdrv_io(bs, sg, sector, bdrv_aio_writev, cb, opaque,
                       DMA_DIRECTION_TO_DEVICE);
}


static uint64_t dma_buf_rw(uint8_t *ptr, int32_t len, QEMUSGList *sg,
                           DMADirection dir)
{
    uint64_t resid;
    int sg_cur_index;

    resid = sg->size;
    sg_cur_index = 0;
    len = MIN(len, resid);
    while (len > 0) {
        ScatterGatherEntry entry = sg->sg[sg_cur_index++];
        int32_t xfer = MIN(len, entry.len);
        dma_memory_rw(sg->as, entry.base, ptr, xfer, dir);
        ptr += xfer;
        len -= xfer;
        resid -= xfer;
    }

    return resid;
}

uint64_t dma_buf_read(uint8_t *ptr, int32_t len, QEMUSGList *sg)
{
    return dma_buf_rw(ptr, len, sg, DMA_DIRECTION_FROM_DEVICE);
}

uint64_t dma_buf_write(uint8_t *ptr, int32_t len, QEMUSGList *sg)
{
    return dma_buf_rw(ptr, len, sg, DMA_DIRECTION_TO_DEVICE);
}

void dma_acct_start(BlockDriverState *bs, BlockAcctCookie *cookie,
                    QEMUSGList *sg, enum BlockAcctType type)
{
    bdrv_acct_start(bs, cookie, sg->size, type);
}
