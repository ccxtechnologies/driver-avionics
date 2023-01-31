/*
 * Copyright (C), 2019 CCX Technologies
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include <linux/module.h>
#include <linux/netdevice.h>
#include <net/sock.h>
#include <net/rtnetlink.h>
#include <linux/skbuff.h>
#include <linux/init.h>
#include <linux/spi/spi.h>
#include <linux/of_gpio.h>
#include <linux/of_irq.h>
#include <linux/interrupt.h>
#include <linux/time.h>
#include <linux/version.h>

#include "avionics.h"
#include "avionics-device.h"

MODULE_DESCRIPTION("HOLT Hi-3593 ARINC-429 Driver");
MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Charles Eidsness <charles@ccxtechnologies.com>");
MODULE_VERSION("1.2.1");

#define HI3593_FIFO_DEPTH	32
#define HI3593_SAMPLE_SIZE	(sizeof(avionics_data))
#define HI3593_MTU		(HI3593_FIFO_DEPTH * HI3593_SAMPLE_SIZE * 8)

#define HI3593_OPCODE_RESET		0x04
#define HI3593_OPCODE_RD_TX_STATUS	0x80
#define HI3593_OPCODE_RD_ALCK		0xd4
#define HI3593_OPCODE_WR_ALCK		0x38

#define HI3593_OPCODE_RD_IRQ		0xd0
#define HI3593_OPCODE_WR_IRQ		0x34

#define HI3593_OPCODE_RD_RX1_CNTRL	0x94
#define HI3593_OPCODE_RD_RX2_CNTRL	0xB4
#define HI3593_OPCODE_RD_TX_CNTRL	0x84

#define HI3593_OPCODE_RD_RX1_STATUS	0x90
#define HI3593_OPCODE_RD_RX2_STATUS	0xb0
#define HI3593_OPCODE_RD_TX_STATUS	0x80

#define HI3593_OPCODE_WR_RX1_CNTRL	0x10
#define HI3593_OPCODE_WR_RX2_CNTRL	0x24
#define HI3593_OPCODE_WR_TX_CNTRL	0x08

#define HI3593_OPCODE_RD_RX1_PRIORITY	0x9c
#define HI3593_OPCODE_RD_RX2_PRIORITY	0xbc
#define HI3593_OPCODE_RD_RX1_FILTERS	0x98
#define HI3593_OPCODE_RD_RX2_FILTERS	0xb8

#define HI3593_OPCODE_WR_RX1_PRIORITY	0x18
#define HI3593_OPCODE_WR_RX2_PRIORITY	0x2c
#define HI3593_OPCODE_WR_RX1_FILTERS	0x14
#define HI3593_OPCODE_WR_RX2_FILTERS	0x28

#define HI3593_OPCODE_WR_TX_FIFO	0x0c
#define HI3593_OPCODE_WR_TX_SEND	0x40

#define HI3593_OPCODE_RD_RX1_FIFO	0xa0
#define HI3593_OPCODE_RD_RX2_FIFO	0xc0

#define HI3593_OPCODE_RD_RX1_PL1	0xa4
#define HI3593_OPCODE_RD_RX2_PL1	0xc4
#define HI3593_OPCODE_RD_RX1_PL2	0xa8
#define HI3593_OPCODE_RD_RX2_PL2	0xc8
#define HI3593_OPCODE_RD_RX1_PL3	0xac
#define HI3593_OPCODE_RD_RX2_PL3	0xcc

#define AVIONICS_ARINC429TX_HIZ		(1<<7)

#define HI3593_FIFO_FULL	0x04
#define HI3593_FIFO_HALF	0x02
#define HI3593_FIFO_EMPTY	0x01

#define HI3593_TX_CNTRL_TMODE	(1<<5)

#define HI3593_PRIORITY_LABEL1	0x08
#define HI3593_PRIORITY_LABEL2	0x10
#define HI3593_PRIORITY_LABEL3	0x20

#define HI3593_NUM_TX	1
#define HI3593_NUM_RX	2

#define HI3593_RX_DELAY_MULTIPLIER_MAX	 ((HI3593_FIFO_DEPTH/2+4)*sizeof(__u32)*1000000)
#define HI3593_RX_DELAY_MULTIPLIER_MIN	 ((HI3593_FIFO_DEPTH/2)*sizeof(__u32)*1000000)
#define HI3593_RX_HALF_FILL_MULTIPLIER	 ((HI3593_FIFO_DEPTH/2+2)*sizeof(__u32)*HZ)

#define HI3593_MAX_SPI_BUFSIZE	16

struct hi3593 {
	struct net_device *rx[HI3593_NUM_RX];
	struct net_device *tx[HI3593_NUM_TX];
	struct workqueue_struct *wq;
	int reset_gpio;
	int irq[2];
	__u32 aclk;
	bool inverted_irqs;
	struct mutex lock;
	atomic_t rx_enabled[2];
};

struct hi3593_priv {
	struct net_device *dev;
	struct spi_device *spi;
	struct sk_buff_head skbq;
	int tx_index;
	int rx_index;
	struct mutex *lock;
	struct workqueue_struct *wq;
	struct delayed_work worker;
	int irq;
	__u8 even_parity;
	__u8 check_parity;
	atomic_t *rx_enabled;
	int rate;
	unsigned long rx_udelay_min;
	unsigned long rx_udelay_max;
	unsigned long rx_wrk_delay;

	/* rx worker spi transfers, used to optimize spi transfers */
	__u8 rx_spi_rx_buffer[HI3593_MAX_SPI_BUFSIZE];
	__u8 rx_spi_tx_buffer[HI3593_MAX_SPI_BUFSIZE];
};

static ssize_t hi3593_get_cntrl(struct hi3593_priv *priv)
{
	__u8 rd_cmd;

	if (priv->tx_index == 0) {
		rd_cmd = HI3593_OPCODE_RD_TX_CNTRL;
	} else if (priv->rx_index == 0) {
		rd_cmd = HI3593_OPCODE_RD_RX1_CNTRL;
	} else if (priv->rx_index == 1) {
		rd_cmd = HI3593_OPCODE_RD_RX2_CNTRL;
	} else {
		pr_err("avionics-hi3593: No valid port index\n");
		return -EINVAL;
	}

	return spi_w8r8(priv->spi, rd_cmd);
}

static int hi3593_set_cntrl(struct hi3593_priv *priv, __u8 value, __u8 mask)
{
	ssize_t status;
	__u8 wr_cmd[2];
	int err;

	status = hi3593_get_cntrl(priv);
	if (status < 0) {
		pr_err("avionics-hi3593: Failed to read control: %zd\n",
		       status);
		return -ENODEV;
	}

	if (priv->tx_index == 0) {
		wr_cmd[0] = HI3593_OPCODE_WR_TX_CNTRL;
	} else if (priv->rx_index == 0) {
		wr_cmd[0] = HI3593_OPCODE_WR_RX1_CNTRL;
	} else if (priv->rx_index == 1) {
		wr_cmd[0] = HI3593_OPCODE_WR_RX2_CNTRL;
	} else {
		pr_err("avionics-hi3593: No valid port index\n");
		return -EINVAL;
	}

	wr_cmd[1] = (status&(~mask)) | (value&mask);
	err = spi_write(priv->spi, wr_cmd, sizeof(wr_cmd));
	if (err < 0) {
		pr_err("avionics-hi3593: Failed to set control\n");
		return err;
	}

	status = hi3593_get_cntrl(priv);
	if (status < 0) {
		pr_err("avionics-hi3593: Failed to read control: %zd\n",
		       status);
		return -ENODEV;
	}

	if ((status&mask) != (value&mask)) {
		pr_err("avionics-hi3593: Failed to set"
		       " control to 0x%x & 0x%x : 0x%zx\n",
		       value, mask, status);
		return -ENODEV;
	}

	return 0;
}

static int hi3593_set_rate(struct avionics_rate *rate,
			   const struct net_device *dev)
{
	struct hi3593_priv *priv;
	__u8 value;
	int err;

	priv = avionics_device_priv(dev);
	if (!priv) {
		pr_err("avionics-hi3593: Failed to get private data\n");
		return -EINVAL;
	}

	if(rate->rate_hz == 100000) {
		value = 0;
	} else if(rate->rate_hz == 12500) {
		value = 1;
	} else {
		pr_warn("avionics-hi3593: speed must be 100000 or 12500 Hz\n");
		return -EINVAL;
	}

	err = hi3593_set_cntrl(priv, value, 0x01);
	if (err < 0) {
		pr_err("avionics-hi3593: Failed to set rate\n");
		return err;
	}

	priv->rate = rate->rate_hz;
	priv->rx_udelay_min = HI3593_RX_DELAY_MULTIPLIER_MIN/priv->rate;
	priv->rx_udelay_max = HI3593_RX_DELAY_MULTIPLIER_MAX/priv->rate;
	priv->rx_wrk_delay = HI3593_RX_HALF_FILL_MULTIPLIER/priv->rate;

	return 0;
}

static void hi3593_get_rate(struct avionics_rate *rate,
			    const struct net_device *dev)
{
	struct hi3593_priv *priv;
	ssize_t status;

	priv = avionics_device_priv(dev);
	if (!priv) {
		pr_err("avionics-hi3593: Failed to get private data\n");
		return;
	}

	status = hi3593_get_cntrl(priv);
	if (status < 0) {
		pr_err("avionics-hi3593: Failed to get rate: %zd\n", status);
	} else if(status&0x0001) {
		rate->rate_hz = 12500;
	} else {
		rate->rate_hz = 100000;
	}

	priv->rate = rate->rate_hz;
	priv->rx_udelay_min = HI3593_RX_DELAY_MULTIPLIER_MIN/priv->rate;
	priv->rx_udelay_max = HI3593_RX_DELAY_MULTIPLIER_MAX/priv->rate;
	priv->rx_wrk_delay = HI3593_RX_HALF_FILL_MULTIPLIER/priv->rate;
}

static void hi3593_get_arinc429rx(struct avionics_arinc429rx *config,
				  const struct net_device *dev)
{
	struct hi3593_priv *priv;
	__u8 rd_priority, rd_filters;
	ssize_t status;
	int err;

	priv = avionics_device_priv(dev);
	if (!priv) {
		pr_err("avionics-hi3593: Failed to get private data\n");
		return;
	}

	status = hi3593_get_cntrl(priv);
	if (status < 0) {
		pr_err("avionics-hi3593: Failed to get rx cntrl: %zd\n",
		       status);
	} else {
		config->flags = (status&0xfe) | priv->even_parity;
	}

	if (priv->rx_index == 0) {
		rd_priority = HI3593_OPCODE_RD_RX1_PRIORITY;
		rd_filters = HI3593_OPCODE_RD_RX1_FILTERS;
	} else if (priv->rx_index == 1) {
		rd_priority = HI3593_OPCODE_RD_RX2_PRIORITY;
		rd_filters = HI3593_OPCODE_RD_RX2_FILTERS;
	} else {
		pr_err("avionics-hi3593: No valid rx port index\n");
		return;
	}

	err = spi_write_then_read(priv->spi, &rd_priority, sizeof(rd_priority),
				  config->priority_labels, 3);
	if (err) {
		pr_err("avionics-hi3593: Failed to get rx priorty labels: %d\n",
		       err);
	}

	err = spi_write_then_read(priv->spi, &rd_filters, sizeof(rd_filters),
				  config->label_filters, 32);
	if (err) {
		pr_err("avionics-hi3593: Failed to get rx label filters: %d\n",
		       err);
	}
}

static int hi3593_set_arinc429rx(struct avionics_arinc429rx *config,
				 const struct net_device *dev)
{
	struct hi3593_priv *priv;
	__u8 wr_priority[4], wr_filters[33];
	int err;

	priv = avionics_device_priv(dev);
	if (!priv) {
		pr_err("avionics-hi3593: Failed to get private data\n");
		return -ENODEV;
	}

	err = hi3593_set_cntrl(priv, config->flags, 0xfe);
	if (err < 0) {
		pr_err("avionics-hi3593: Failed to set rx control.\n");
		return err;
	}

	if(config->flags & AVIONICS_ARINC429RX_EVEN_PARITY) {
		priv->even_parity = AVIONICS_ARINC429RX_EVEN_PARITY;
	} else {
		priv->even_parity = 0;
	}

	if(config->flags & AVIONICS_ARINC429RX_PARITY_CHECK) {
		priv->check_parity = AVIONICS_ARINC429RX_PARITY_CHECK;
	} else {
		priv->check_parity = 0;
	}

	if (priv->rx_index == 0) {
		wr_priority[0] = HI3593_OPCODE_WR_RX1_PRIORITY;
		wr_filters[0] = HI3593_OPCODE_WR_RX1_FILTERS;
	} else if (priv->rx_index == 1) {
		wr_priority[0] = HI3593_OPCODE_WR_RX2_PRIORITY;
		wr_filters[0] = HI3593_OPCODE_WR_RX2_FILTERS;
	} else {
		pr_err("avionics-hi3593: No valid rx port index\n");
		return -EINVAL;
	}

	memcpy(&wr_priority[1], config->priority_labels, 3);
	err = spi_write(priv->spi, wr_priority, sizeof(wr_priority));
	if (err < 0) {
		pr_err("avionics-hi3593: Failed to set priority.\n");
		return err;
	}

	memcpy(&wr_filters[1], config->label_filters, 32);
	err = spi_write(priv->spi, wr_filters, sizeof(wr_filters));
	if (err < 0) {
		pr_err("avionics-hi3593: Failed to set priority.\n");
		return err;
	}

	return 0;
}

static void hi3593_get_arinc429tx(struct avionics_arinc429tx *config,
				  const struct net_device *dev)
{
	struct hi3593_priv *priv;
	ssize_t status;

	priv = avionics_device_priv(dev);
	if (!priv) {
		pr_err("avionics-hi3593: Failed to get private data\n");
		return;
	}


	status = hi3593_get_cntrl(priv);
	if (status < 0) {
		pr_err("avionics-hi3593: Failed to get tx cntrl: %zd\n",
		       status);
	} else {
		config->flags = status&0xfe;
	}

}

static int hi3593_set_arinc429tx(struct avionics_arinc429tx *config,
				 const struct net_device *dev)
{
	struct hi3593_priv *priv;
	int err;

	priv = avionics_device_priv(dev);
	if (!priv) {
		pr_err("avionics-hi3593: Failed to get private data\n");
		return -ENODEV;
	}

	err = hi3593_set_cntrl(priv, config->flags | HI3593_TX_CNTRL_TMODE,
			       0x5c | HI3593_TX_CNTRL_TMODE);
	if (err < 0) {
		pr_err("avionics-hi3593: Failed to set tx cntrl.\n");
		return err;
	}

	return 0;
}

static struct avionics_ops hi3593_arinc429rx_ops = {
	.name = "arinc429rx%d",
	.set_rate = hi3593_set_rate,
	.get_rate = hi3593_get_rate,
	.get_arinc429rx = hi3593_get_arinc429rx,
	.set_arinc429rx = hi3593_set_arinc429rx,
};

static struct avionics_ops hi3593_arinc429tx_ops = {
	.name = "arinc429tx%d",
	.set_rate = hi3593_set_rate,
	.get_rate = hi3593_get_rate,
	.get_arinc429tx = hi3593_get_arinc429tx,
	.set_arinc429tx = hi3593_set_arinc429tx,
};

static int hi3593_change_mtu(struct net_device *dev, int mtu)
{
	if (mtu != HI3593_MTU) {
		pr_err("avionics-hi3593: MTU must be %zd.\n", HI3593_MTU);
		return -EINVAL;
	}

	return 0;
}

static int hi3593_tx_open(struct net_device *dev)
{
	struct hi3593_priv *priv;
	int err;

	pr_warn("avionics-hi3593: Enabling Driver\n");

	priv = avionics_device_priv(dev);
	if (!priv) {
		pr_err("avionics-hi3593: Failed to get private data\n");
		return -EINVAL;
	}

	err = hi3593_set_cntrl(priv, 0, AVIONICS_ARINC429TX_HIZ);
	if (err < 0) {
		pr_err("avionics-hi3593: Failed to enable driver\n");
		return err;
	}

	netif_wake_queue(dev);

	return 0;
}

static int hi3593_tx_stop(struct net_device *dev)
{
	struct hi3593_priv *priv;
	int err;

	pr_warn("avionics-hi3593: Disabling Driver\n");

	netif_stop_queue(dev);

	priv = avionics_device_priv(dev);
	if (!priv) {
		pr_err("avionics-hi3593: Failed to get private data\n");
		return -EINVAL;
	}

	skb_queue_purge(&priv->skbq);

	err = hi3593_set_cntrl(priv, AVIONICS_ARINC429TX_HIZ,
			       AVIONICS_ARINC429TX_HIZ);
	if (err < 0) {
		pr_err("avionics-hi3593: Failed to disable driver\n");
		return err;
	}

	return 0;
}

static void hi3593_empty_fifo(struct hi3593_priv *priv);

static int hi3593_rx_open(struct net_device *dev)
{
	struct hi3593_priv *priv;

	priv = avionics_device_priv(dev);
	if (!priv) {
		pr_err("avionics-hi3593: Failed to get private data\n");
		return -EINVAL;
	}

	pr_warn("avionics-hi3593: Enabling Receiver\n");

	if (atomic_read(priv->rx_enabled)) {
		pr_err("avionics-hi3593: Receiver already running\n");
		return 0;
	}


	atomic_set(priv->rx_enabled, 1);

	mutex_lock(priv->lock);

	enable_irq(priv->irq);
	hi3593_empty_fifo(priv);

	mutex_unlock(priv->lock);

	return 0;
}

static int hi3593_rx_stop(struct net_device *dev)
{
	struct hi3593_priv *priv;

	priv = avionics_device_priv(dev);
	if (!priv) {
		pr_err("avionics-hi3593: Failed to get private data\n");
		return -EINVAL;
	}

	pr_warn("avionics-hi3593: Disabling Receiver\n");

	if (!atomic_read(priv->rx_enabled)) {
		return 0;
	}

	netif_stop_queue(dev);

	atomic_set(priv->rx_enabled, 0);

	return 0;
}

int hi3593_rx_worker_spi_write_then_read(
			struct hi3593_priv *priv,
			const void *txbuf, unsigned n_tx,
			void *rxbuf, unsigned n_rx)
{
	int status;
	struct spi_message	message;
	struct spi_transfer	transfer;

	if ((n_rx + n_tx) > HI3593_MAX_SPI_BUFSIZE) {
		pr_err("avionics-hi3593: message size too long\n");
		return -1;
	}

	spi_message_init(&message);
	memset(&transfer, 0, sizeof(transfer));

	transfer.len = n_tx + n_rx;
	spi_message_add_tail(&transfer, &message);

	memcpy(priv->rx_spi_tx_buffer, txbuf, n_tx);
	transfer.tx_buf = priv->rx_spi_tx_buffer;
	transfer.rx_buf = priv->rx_spi_rx_buffer;

	status = spi_sync(priv->spi, &message);
	if (status < 0) {
		pr_err("avionics-hi3593: spi transfer failed\n");
	} else {
		memcpy(rxbuf, transfer.rx_buf+n_tx, n_rx);
	}

	return status;
}

static void hi3593_empty_fifo(struct hi3593_priv *priv)
{
	avionics_data *data;
	__u8 status_cmd, rd_cmd, buffer[4];
	__u8 pl_cmd[3], pl_rd, pl[3];
	const __u8 pl_bits[3] = {HI3593_PRIORITY_LABEL1,
		HI3593_PRIORITY_LABEL2, HI3593_PRIORITY_LABEL3};
	ssize_t status;
	int err, i;

	if (priv->rx_index == 0) {
		rd_cmd = HI3593_OPCODE_RD_RX1_FIFO;
		status_cmd = HI3593_OPCODE_RD_RX1_STATUS;
		pl_cmd[0] = HI3593_OPCODE_RD_RX1_PL1;
		pl_cmd[1] = HI3593_OPCODE_RD_RX1_PL2;
		pl_cmd[2] = HI3593_OPCODE_RD_RX1_PL3;
		pl_rd = HI3593_OPCODE_RD_RX1_PRIORITY;
	} else if (priv->rx_index == 1) {
		rd_cmd = HI3593_OPCODE_RD_RX2_FIFO;
		status_cmd = HI3593_OPCODE_RD_RX2_STATUS;
		pl_cmd[0] = HI3593_OPCODE_RD_RX2_PL1;
		pl_cmd[1] = HI3593_OPCODE_RD_RX2_PL2;
		pl_cmd[2] = HI3593_OPCODE_RD_RX2_PL3;
		pl_rd = HI3593_OPCODE_RD_RX2_PRIORITY;
	} else {
		pr_err("avionics-hi3593: No valid port index\n");
		return;
	}

	data = kmalloc(HI3593_MTU, GFP_KERNEL);
	if (data == NULL) {
		pr_err("avionics-hi3593: Failed to allocate data buffer\n");
		return;
	}

	err = hi3593_rx_worker_spi_write_then_read(priv,
					&status_cmd, sizeof(status_cmd), &status, sizeof(status));
	if (err < 0) {
		pr_err("avionics-hi3593: Failed to read status\n");
		goto done;
	}

	if (status & (pl_bits[0] | pl_bits[1] | pl_bits[2])) {
		err = hi3593_rx_worker_spi_write_then_read(priv, &pl_rd, sizeof(pl_rd),
					  pl, sizeof(pl));
		if (unlikely(err)) {
			pr_err("avionics-hi3593: Failed to"
			       " read priority labels\n");
			goto done;
		}
	}

	for (i = 0; i < 3; i++) {
		if (status & pl_bits[i]) {
			buffer[3] = pl[2-i];
			err = hi3593_rx_worker_spi_write_then_read(priv, &pl_cmd[i],
						  sizeof(pl_cmd[0]), buffer,
						  sizeof(buffer) - 1);
			if (unlikely(err)) {
				pr_err("avionics-hi3593: Failed to"
				       " read priority label\n");
				goto done;
			}
		}
	}

    i = 0;
	while (!(status & HI3593_FIFO_EMPTY)) {
        err = hi3593_rx_worker_spi_write_then_read(priv,
                      &rd_cmd, sizeof(rd_cmd),
                      buffer, sizeof(buffer));
        if (unlikely(err)) {
            pr_err("avionics-hi3593: Failed to"
                   " read from fifo\n");
            goto done;
        }

        err = hi3593_rx_worker_spi_write_then_read(priv,
                &status_cmd, sizeof(status_cmd), &status, sizeof(status));
        if (unlikely(err < 0)) {
            pr_err("avionics-hi3593: Failed to"
                   " read status\n");
            goto done;
        }

        i++;
        if (i > 10000) {
            pr_err("avionics-hi3593: Failed to clear FIFO\n");
            goto done;
        }

	}

    pr_info("avionics-hi3593: Emptied FIFO in %d\n", i);

done:
	kfree(data);

}

static void hi3593_rx_worker(struct work_struct *work)
{
	struct net_device *dev;
	struct net_device_stats *stats;
	struct hi3593_priv *priv;
	struct sk_buff *skb;
	struct timespec64 tv;
	avionics_data *data;
	__u32 vbuffer;
	__u8 status_cmd, rd_cmd, buffer[4];
	__u8 pl_cmd[3], pl_rd, pl[3];
	const __u8 pl_bits[3] = {HI3593_PRIORITY_LABEL1,
		HI3593_PRIORITY_LABEL2, HI3593_PRIORITY_LABEL3};
	ssize_t status;
	int err, i, cnt;

	priv = container_of((struct delayed_work*)work,
			    struct hi3593_priv, worker);
	dev = priv->dev;
	stats = &dev->stats;

	priv = avionics_device_priv(dev);
	if (!priv) {
		pr_err("avionics-hi3593: Failed to get private data\n");
		return;
	}

	if (priv->rx_index == 0) {
		rd_cmd = HI3593_OPCODE_RD_RX1_FIFO;
		status_cmd = HI3593_OPCODE_RD_RX1_STATUS;
		pl_cmd[0] = HI3593_OPCODE_RD_RX1_PL1;
		pl_cmd[1] = HI3593_OPCODE_RD_RX1_PL2;
		pl_cmd[2] = HI3593_OPCODE_RD_RX1_PL3;
		pl_rd = HI3593_OPCODE_RD_RX1_PRIORITY;
	} else if (priv->rx_index == 1) {
		rd_cmd = HI3593_OPCODE_RD_RX2_FIFO;
		status_cmd = HI3593_OPCODE_RD_RX2_STATUS;
		pl_cmd[0] = HI3593_OPCODE_RD_RX2_PL1;
		pl_cmd[1] = HI3593_OPCODE_RD_RX2_PL2;
		pl_cmd[2] = HI3593_OPCODE_RD_RX2_PL3;
		pl_rd = HI3593_OPCODE_RD_RX2_PRIORITY;
	} else {
		pr_err("avionics-hi3593: No valid port index\n");
		return;
	}

	data = kmalloc(HI3593_MTU, GFP_KERNEL);
	if (data == NULL) {
		pr_err("avionics-hi3593: Failed to allocate data buffer\n");
		return;
	}

	mutex_lock(priv->lock);

	err = hi3593_rx_worker_spi_write_then_read(priv,
					&status_cmd, sizeof(status_cmd), &status, sizeof(status));
	if (err < 0) {
		pr_err("avionics-hi3593: Failed to read status\n");
		goto done;
	}

	if (status & HI3593_FIFO_FULL) {
		stats->rx_errors++;
		stats->rx_fifo_errors++;
	}

	if (status & (pl_bits[0] | pl_bits[1] | pl_bits[2])) {
		err = hi3593_rx_worker_spi_write_then_read(priv, &pl_rd, sizeof(pl_rd),
					  pl, sizeof(pl));
		if (unlikely(err)) {
			pr_err("avionics-hi3593: Failed to"
			       " read priority labels\n");
			goto done;
		}
	}

	for (i = 0; i < 3; i++) {
		if (status & pl_bits[i]) {
			buffer[3] = pl[2-i];
			err = hi3593_rx_worker_spi_write_then_read(priv, &pl_cmd[i],
						  sizeof(pl_cmd[0]), buffer,
						  sizeof(buffer) - 1);
			if (unlikely(err)) {
				pr_err("avionics-hi3593: Failed to"
				       " read priority label\n");
				goto done;
			}

			if(!priv->check_parity ||
			   (priv->even_parity && (0x80&buffer[0])) ||
			   ((0x80&buffer[0]) == 0x00)) {
				if (priv->check_parity && priv->even_parity) {
					buffer[0] &= 0x7f;
				}

				skb = avionics_device_alloc_skb(dev, HI3593_SAMPLE_SIZE);
				if (unlikely(!skb)) {
					pr_err("avionics-hi3593: Failed to"
					       " allocate RX buffer\n");
					goto done;
				}

				ktime_get_real_ts64(&tv);
				data[0].time_msecs = (tv.tv_sec*MSEC_PER_SEC) +
					(tv.tv_nsec/NSEC_PER_MSEC);
				vbuffer = buffer[0] + (buffer[1]<<8) +
					  (buffer[2]<<16) + (buffer[3]<<24);
				data[0].value = be32_to_cpu(vbuffer);

				skb_copy_to_linear_data(skb, data, HI3593_SAMPLE_SIZE);

				stats->rx_packets++;
				stats->rx_bytes += skb->len;
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,18,0)
				netif_rx_ni(skb);
#else
				netif_rx(skb);
#endif
			} else {
				stats->rx_errors++;
				stats->rx_crc_errors++;
			}
		}
	}

	cnt = 0;
	if (!(status & HI3593_FIFO_EMPTY)) {
		for (i = 0; i < HI3593_MTU; i += HI3593_SAMPLE_SIZE) {

			err = hi3593_rx_worker_spi_write_then_read(priv,
						  &rd_cmd, sizeof(rd_cmd),
						  buffer, sizeof(buffer));
			if (unlikely(err)) {
				pr_err("avionics-hi3593: Failed to"
				       " read from fifo\n");
				goto done;
			}

			if(!priv->check_parity ||
			   (priv->even_parity && (0x80&buffer[0])) ||
			   ((0x80&buffer[0]) == 0x00)) {
				if (priv->check_parity && priv->even_parity) {
					buffer[0] &= 0x7f;
				}

				ktime_get_real_ts64(&tv);
				data[cnt].time_msecs = (tv.tv_sec*MSEC_PER_SEC) +
					(tv.tv_nsec/NSEC_PER_MSEC);
				vbuffer = buffer[0] + (buffer[1]<<8) +
					  (buffer[2]<<16) + (buffer[3]<<24);
				data[cnt].value = be32_to_cpu(vbuffer);

				cnt++;

			} else {
				stats->rx_errors++;
				stats->rx_crc_errors++;
			}

			err = hi3593_rx_worker_spi_write_then_read(priv,
					&status_cmd, sizeof(status_cmd), &status, sizeof(status));
			if (unlikely(err < 0)) {
				pr_err("avionics-hi3593: Failed to"
				       " read status\n");
				goto done;
			}

			if(status & HI3593_FIFO_EMPTY) {
				usleep_range(priv->rx_udelay_min,
					     priv->rx_udelay_max);
				err = hi3593_rx_worker_spi_write_then_read(priv,
					&status_cmd, sizeof(status_cmd), &status, sizeof(status));
				if (unlikely(err < 0)) {
					pr_err("avionics-hi3593: Failed to"
					       " read status\n");
					goto done;
				}
				if(status & HI3593_FIFO_EMPTY) {
					break;
				}
			}
		}

		if (cnt) {
			skb = avionics_device_alloc_skb(dev, cnt*HI3593_SAMPLE_SIZE);
			if (unlikely(!skb)) {
				pr_err("avionics-lb: Failed to"
				       " allocate RX buffer\n");
				goto done;
			}

			skb_copy_to_linear_data(skb, data, cnt*HI3593_SAMPLE_SIZE);

			stats->rx_packets++;
			stats->rx_bytes += skb->len;
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,18,0)
			netif_rx_ni(skb);
#else
			netif_rx(skb);
#endif
		}
	}

done:
	mutex_unlock(priv->lock);
	kfree(data);
	enable_irq(priv->irq);

}

static irqreturn_t hi3593_rx_irq(int irq, void *data)
{
	struct hi3593_priv *priv = data;

	if (unlikely(irq != priv->irq)) {
		pr_err("avionics-hi3593: Unexpected irq %d\n", irq);
		return IRQ_HANDLED;
	}

	disable_irq_nosync(priv->irq);

	if (atomic_read(priv->rx_enabled)) {
		queue_delayed_work(priv->wq, &priv->worker, priv->rx_wrk_delay);
	}

	return IRQ_HANDLED;
}

static void hi3593_tx_worker(struct work_struct *work)
{
	struct net_device *dev;
	struct net_device_stats *stats;
	struct hi3593_priv *priv;
	struct sk_buff *skb;
	avionics_data *data;
	__u8 rd_cmd, wr_cmd[5];
	__u32 vbuffer;
	__u64 time_msecs, offset_msecs;
	ssize_t status;
	struct timespec64 tv;
	int err, i;

	priv = container_of((struct delayed_work*)work,
			    struct hi3593_priv, worker);
	dev = priv->dev;
	stats = &dev->stats;

	priv = avionics_device_priv(dev);
	if (!priv) {
		pr_err("avionics-hi3593: Failed to get private data\n");
		return;
	}

	if (priv->tx_index == 0) {
		rd_cmd = HI3593_OPCODE_RD_TX_STATUS;
	} else {
		pr_err("avionics-hi3593: No valid port index\n");
		return;
	}

	skb = skb_dequeue(&priv->skbq);
	if (!skb) {
		return;
	}

	wr_cmd[0] = HI3593_OPCODE_WR_TX_FIFO;
	data = (avionics_data *)skb->data;
	for (i = 0; i < skb->len/sizeof(data[0]); i++) {
		status = spi_w8r8(priv->spi, rd_cmd);
		if (status < 0) {
			pr_err("avionics-hi3593: Failed to read status\n");
			return;
		}

		if (status & HI3593_FIFO_FULL) {
			usleep_range(priv->rx_udelay_min, priv->rx_udelay_max);

			status = spi_w8r8(priv->spi, rd_cmd);
			if (status < 0) {
				pr_err("avionics-hi3593: Failed to read status\n");
				return;
			}

			if (status & HI3593_FIFO_FULL) {
				pr_err("avionics-hi3593: TX fifo overflow\n");
				stats->tx_dropped++;
				consume_skb(skb);
				return;
			}
		}

		vbuffer = cpu_to_be32(data[i].value);
		wr_cmd[1] = (vbuffer&0x000000ff);
		wr_cmd[2] = (vbuffer&0x0000ff00) >> 8;
		wr_cmd[3] = (vbuffer&0x00ff0000) >> 16;
		wr_cmd[4] = (vbuffer&0xff000000) >> 24;

		if (data[i].time_msecs) {
			ktime_get_real_ts64(&tv);
			time_msecs = (tv.tv_sec*MSEC_PER_SEC) +
				(tv.tv_nsec/NSEC_PER_MSEC);
			if (time_msecs < data[i].time_msecs) {
				offset_msecs = data[i].time_msecs - time_msecs;
				if (offset_msecs > 360000) {
					pr_err("avionics-hi3593-tx: Offset %llu"
					       " too large, ignoring\n",
					       offset_msecs) ;
				} else if (offset_msecs > 2) {
					usleep_range((offset_msecs*1000 - 500),
						     (offset_msecs*1000 + 500));
				}
			}
		}

		err = spi_write(priv->spi, &wr_cmd, sizeof(wr_cmd));
		if (err < 0) {
			pr_err("avionics-hi3593: Failed to load fifo\n");
			return;
		}
	}

	stats->tx_packets++;
	stats->tx_bytes += skb->len;

	consume_skb(skb);
}

static netdev_tx_t hi3593_tx_start_xmit(struct sk_buff *skb,
					struct net_device *dev)
{
	struct net_device_stats *stats = &dev->stats;
	struct hi3593_priv *priv;

	if (skb->protocol != htons(ETH_P_AVIONICS)) {
		kfree_skb(skb);
		stats->tx_dropped++;
		return NETDEV_TX_OK;
	}

	if (unlikely(skb->len > HI3593_MTU)) {
		kfree_skb(skb);
		stats->tx_dropped++;
		return NETDEV_TX_OK;
	}

	if (unlikely(skb->len % sizeof(avionics_data))) {
		kfree_skb(skb);
		stats->tx_dropped++;
		return NETDEV_TX_OK;
	}

	priv = avionics_device_priv(dev);
	if (!priv) {
		pr_err("avionics-hi3593: Failed to get private data\n");
		kfree_skb(skb);
		stats->tx_dropped++;
		return NETDEV_TX_OK;
	}

	skb_queue_tail(&priv->skbq, skb);
	queue_delayed_work(priv->wq, &priv->worker, 0);

	return NETDEV_TX_OK;
}

static const struct net_device_ops hi3593_tx_netdev_ops = {
	.ndo_change_mtu = hi3593_change_mtu,
	.ndo_open = hi3593_tx_open,
	.ndo_stop = hi3593_tx_stop,
	.ndo_start_xmit = hi3593_tx_start_xmit,
};

static const struct net_device_ops hi3593_rx_netdev_ops = {
	.ndo_change_mtu = hi3593_change_mtu,
	.ndo_open = hi3593_rx_open,
	.ndo_stop = hi3593_rx_stop,
};

static const struct of_device_id hi3593_of_device_id[] = {
	{ .compatible	= "holt,hi3593" },
	{}
};
MODULE_DEVICE_TABLE(of, hi3593_of_device_id);

static const struct spi_device_id hi3593_spi_device_id[] = {
	{
		.name		= "hi3593",
		.driver_data	= (kernel_ulong_t)0,
	},
	{}
};
MODULE_DEVICE_TABLE(spi, hi3593_spi_device_id);

static int hi3593_get_config(struct spi_device *spi)
{
	struct hi3593 *hi3593 = spi_get_drvdata(spi);
	struct device *dev = &spi->dev;
	int err, i;

	hi3593->reset_gpio = of_get_named_gpio(dev->of_node, "reset-gpio", 0);
	if (hi3593->reset_gpio > 0 ) {
		if (!gpio_is_valid(hi3593->reset_gpio)) {
			pr_err("avionics-hi3593: Reset GPIO is not valid\n");
			return -EINVAL;
		}

		err = devm_gpio_request_one(&spi->dev, hi3593->reset_gpio,
					    GPIOF_OUT_INIT_HIGH, "reset");
		if (err) {
			pr_err("avionics-hi3593: Failed to"
			       " register Reset GPIO\n");
			return err;
		}
	}

	err = of_property_read_u32(dev->of_node, "aclk", &hi3593->aclk);
	if (err) {
		pr_err("avionics-hi3593: Failed to get aclk"
		       " frequency from dts: %d\n",err);
		return err;
	}

	for (i = 0; i < HI3593_NUM_RX; i++) {
		hi3593->irq[i] = irq_of_parse_and_map(dev->of_node, i);
		if (hi3593->irq[i] < 0) {
			pr_err("avionics-hi3593: Failed to"
			       " get irq %d: %d\n", i, hi3593->irq[i]);
			return hi3593->irq[i];
		}
	}

	hi3593->inverted_irqs = of_property_read_bool(dev->of_node, "inverted-irqs");

	return 0;
}

static int hi3593_reset(struct spi_device *spi)
{
	struct hi3593 *hi3593 = spi_get_drvdata(spi);
	__u8 opcode, wr_cmd[2];
	ssize_t status;
	int err;

	if (hi3593->reset_gpio <= 0 ) {
		pr_warn("avionics-hi3593: Reset GPIO Reset missing/malformed,"
		       " will use reset command.\n");
		hi3593->reset_gpio = 0;
		opcode = HI3593_OPCODE_RESET;
		err = spi_write(spi, &opcode, sizeof(opcode));
		if (err < 0) {
			pr_err("avionics-hi3593: Failed to"
			       " send reset command\n");
			return err;
		}

	} else {
		err = gpio_direction_output(hi3593->reset_gpio, 1);
		if (err < 0) {
			pr_err("avionics-hi3593: Failed to set gpio reset\n");
			return err;
		}
		usleep_range(100, 150);
		err = gpio_direction_output(hi3593->reset_gpio, 0);
		if (err < 0) {
			pr_err("avionics-hi3593: Failed to clear gpio reset\n");
			return err;
		}
	}

	/* Default to high-impdance driver */
	wr_cmd[0] = HI3593_OPCODE_WR_TX_CNTRL;
	wr_cmd[1] = AVIONICS_ARINC429TX_HIZ;

	err = spi_write(spi, wr_cmd, sizeof(wr_cmd));
	if (err < 0) {
		pr_err("avionics-hi3593: Failed to disable driver\n");
		return err;
	}

	status = spi_w8r8(spi, HI3593_OPCODE_RD_TX_STATUS);
	if (status != 0x01) {
		pr_err("avionics-hi3593: TX FIFO is not cleared: %zx\n",
		       status);
		return -ENODEV;
	}

	pr_info("avionics-hi3593: Device up\n");
	return 0;
}

static int hi3593_set_aclk(struct spi_device *spi)
{
	struct hi3593 *hi3593 = spi_get_drvdata(spi);
	int err;
	__u8 cmd[2];
	ssize_t status;

	if ((hi3593->aclk < 1000000) || (hi3593->aclk > 30000000)) {
		pr_err("avionics-hi3593: aclk must be between"
		       " 1000000 and 30000000 (1MHz - 30MHz)\n");
		return -EINVAL;
	}

	if ((hi3593->aclk != 1000000) && (hi3593->aclk % 2000000)) {
		pr_err("avionics-hi3593: aclk must be either 1000000"
		       " or a multiple of 2000000\n");
		return -EINVAL;
	}

	cmd[0] = HI3593_OPCODE_WR_ALCK;
	if (hi3593->aclk == 1000000) {
		cmd[1] = 0x00;
	} else {
		cmd[1] = hi3593->aclk/1000000;
	}

	err = spi_write(spi, &cmd, sizeof(cmd));
	if (err < 0) {
		pr_err("avionics-hi3593: Failed to send aclk set command\n");
		return err;
	}

	status = spi_w8r8(spi, HI3593_OPCODE_RD_ALCK);
	if (status != cmd[1]) {
		pr_err("avionics-hi3593: ALCK not set to 0x%x: 0x%zx\n",
		       cmd[1], status);
		return -ENODEV;
	}

	pr_info("avionics-hi3593: ALCK set to 0x%zx\n", status);

	return 0;
}

static struct avionics_arinc429rx avionics_arinc429rx_default = {
	.flags = (AVIONICS_ARINC429RX_FLIP_LABEL_BITS |
		  AVIONICS_ARINC429RX_PARITY_CHECK),
	.priority_labels = {0,0,0},
	.label_filters = {0,0,0,0,0,0,0,0,
		0,0,0,0,0,0,0,0,
		0,0,0,0,0,0,0,0,
		0,0,0,0,0,0,0,0},
};

static struct avionics_arinc429tx avionics_arinc429tx_default = {
	.flags = (AVIONICS_ARINC429TX_FLIP_LABEL_BITS |
		  AVIONICS_ARINC429TX_PARITY_SET |
		  AVIONICS_ARINC429TX_HIZ),
};

static int hi3593_create_netdevs(struct spi_device *spi)
{
	struct hi3593 *hi3593 = spi_get_drvdata(spi);
	struct hi3593_priv *priv;
	int i, err;
	unsigned long irq_flags;

	if (hi3593->inverted_irqs) {
		pr_info("Expecting IRQs to be inverted in hardware\n");
		irq_flags = IRQF_TRIGGER_FALLING | IRQF_ONESHOT| IRQF_NO_AUTOEN;
	} else {
		irq_flags = IRQF_TRIGGER_RISING | IRQF_ONESHOT| IRQF_NO_AUTOEN;
	}

	hi3593->wq = alloc_workqueue("hi3593", WQ_HIGHPRI, 0);
	if (!hi3593->wq) {
		pr_err("avionics-hi3593: Failed to allocate work-queue\n");
		return -ENOMEM;
	}

	for (i = 0; i < HI3593_NUM_TX; i++) {
		hi3593->tx[i] = avionics_device_alloc(sizeof(*priv),
						      &hi3593_arinc429tx_ops);
		if (!hi3593->tx[i] ) {
			pr_err("avionics-hi3593: Failed to allocate"
			       " TX %d netdev\n", i);
			return -ENOMEM;
		}

		hi3593->tx[i]->netdev_ops = &hi3593_tx_netdev_ops;
		hi3593->tx[i]->mtu = HI3593_MTU;
		priv = avionics_device_priv(hi3593->tx[i]);

		if (!priv) {
			pr_err("avionics-hi3593: Failed to get private data"
			       " for TX %d\n", i);
			return -EINVAL;
		}
		priv->dev = hi3593->tx[i];
		priv->spi = spi;
		priv->lock = &hi3593->lock;
		priv->tx_index = i;
		priv->rx_index = -1;
		skb_queue_head_init(&priv->skbq);
		priv->wq = hi3593->wq;
		priv->rate = 12500;
		priv->rx_udelay_min = HI3593_RX_DELAY_MULTIPLIER_MIN/priv->rate;
		priv->rx_udelay_max = HI3593_RX_DELAY_MULTIPLIER_MAX/priv->rate;
		priv->rx_wrk_delay = HI3593_RX_HALF_FILL_MULTIPLIER/priv->rate;

		INIT_DELAYED_WORK(&priv->worker, hi3593_tx_worker);

		err = hi3593_set_arinc429tx(&avionics_arinc429tx_default,
					    hi3593->tx[i]);
		if (err) {
			pr_err("avionics-hi3593: Failed to set TX %d"
			       " default settings\n", i);
			return -EINVAL;
		}

		err = avionics_device_register(hi3593->tx[i]);
		if (err) {
			pr_err("avionics-hi3593: Failed to register"
			       " TX %d netdev\n", i);
			return -EINVAL;
		}

	}

	for (i = 0; i < HI3593_NUM_RX; i++) {
		hi3593->rx[i] = avionics_device_alloc(sizeof(*priv),
						      &hi3593_arinc429rx_ops);
		if (!hi3593->rx[i] ) {
			pr_err("avionics-hi3593: Failed to allocate"
			       " RX %d netdev\n", i);
			return -ENOMEM;
		}

		hi3593->rx[i]->netdev_ops = &hi3593_rx_netdev_ops;
		hi3593->rx[i]->mtu = HI3593_MTU;
		priv = avionics_device_priv(hi3593->rx[i]);

		if (!priv) {
			pr_err("avionics-hi3593: Failed to get private data"
			       " for RX %d\n", i);
			return -EINVAL;
		}
		priv->dev = hi3593->rx[i];
		priv->spi = spi;
		priv->lock = &hi3593->lock;
		priv->tx_index = -1;
		priv->rx_index = i;
		priv->rx_enabled = &hi3593->rx_enabled[i];
		skb_queue_head_init(&priv->skbq);
		priv->wq = hi3593->wq;
		priv->rate = 12500;
		priv->rx_udelay_min = HI3593_RX_DELAY_MULTIPLIER_MIN/priv->rate;
		priv->rx_udelay_max = HI3593_RX_DELAY_MULTIPLIER_MAX/priv->rate;
		priv->rx_wrk_delay = HI3593_RX_HALF_FILL_MULTIPLIER/priv->rate;

		INIT_DELAYED_WORK(&priv->worker, hi3593_rx_worker);

		err = request_irq(hi3593->irq[i], hi3593_rx_irq,
				  irq_flags, hi3593->rx[i]->name, priv);
		if (err) {
			pr_err("avionics-hi3593: Failed to register"
			       " RX %d irq %d\n", i, hi3593->irq[i]);
			return -EINVAL;
		}
		priv->irq = hi3593->irq[i];

		err = hi3593_set_arinc429rx(&avionics_arinc429rx_default,
					    hi3593->rx[i]);
		if (err) {
			pr_err("avionics-hi3593: Failed to set RX %d"
			       " default settings\n", i);
			return -EINVAL;
		}

		err = avionics_device_register(hi3593->rx[i]);
		if (err) {
			pr_err("avionics-hi3593: Failed to register"
			       " RX %d netdev\n", i);
			return -EINVAL;
		}

	}

	return 0;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(5,18,0)
static int hi3593_remove(struct spi_device *spi)
#else
static void hi3593_remove(struct spi_device *spi)
#endif
{
	struct hi3593 *hi3593 = spi_get_drvdata(spi);
	struct hi3593_priv *priv;
	int i;

	pr_info("avionics-hi3593: Removing Device\n");

	for (i = 0; i < HI3593_NUM_TX; i++) {
		if (hi3593->tx[i]) {
			priv = avionics_device_priv(hi3593->tx[i]);
			if (priv) {
				skb_queue_purge(&priv->skbq);
				cancel_delayed_work_sync(&priv->worker);
			}
			avionics_device_unregister(hi3593->tx[i]);
			avionics_device_free(hi3593->tx[i]);
			hi3593->tx[i] = NULL;
		}
	}

	for (i = 0; i < HI3593_NUM_RX; i++) {
		if (hi3593->rx[i]) {
			atomic_set(&hi3593->rx_enabled[i], 0);
			priv = avionics_device_priv(hi3593->rx[i]);
			if (priv) {
				skb_queue_purge(&priv->skbq);
				if (priv->irq) {
					free_irq(priv->irq, priv);
				}
				cancel_delayed_work_sync(&priv->worker);
			}
			avionics_device_unregister(hi3593->rx[i]);
			avionics_device_free(hi3593->rx[i]);
			hi3593->rx[i] = 0;
		}
	}

	if (hi3593->reset_gpio > 0) {
		if (gpio_direction_output(hi3593->reset_gpio, 1) < 0) {
			pr_err("avionics-hi3593: Failed to set gpio reset\n");
		}
		gpio_free(hi3593->reset_gpio);
		hi3593->reset_gpio = 0;
	}

	if (hi3593->wq) {
		flush_scheduled_work();
		flush_workqueue(hi3593->wq);
		destroy_workqueue(hi3593->wq);
	}

#if LINUX_VERSION_CODE < KERNEL_VERSION(5,18,0)
	return 0;
#endif
}

static int hi3593_probe(struct spi_device *spi)
{
	struct hi3593 *hi3593;
	struct device *dev = &spi->dev;
	int err;

	pr_info("avionics-hi3593: Adding Device\n");

	hi3593 = devm_kzalloc(dev, sizeof(*hi3593), GFP_KERNEL);
	if (!hi3593) {
		pr_err("avionics-hi3593: Failed to allocate hi3593 memory\n");
		return -ENOMEM;
	}
	spi_set_drvdata(spi, hi3593);
	mutex_init(&hi3593->lock);
	atomic_set(&hi3593->rx_enabled[0], 0);
	atomic_set(&hi3593->rx_enabled[1], 0);

	err = hi3593_get_config(spi);
	if (err) {
		pr_err("avionics-hi3593: Failed to get system configuration"
		       " from dts file: %d\n",err);
		hi3593_remove(spi);
		return err;
	}

	err = hi3593_reset(spi);
	if (err) {
		pr_err("avionics-hi3593: Failed to bring device"
		       " out of reset: %d\n",err);
		hi3593_remove(spi);
		return err;
	}

	err = hi3593_set_aclk(spi);
	if (err) {
		pr_err("avionics-hi3593: Failed to set"
		       " aclk divider: %d\n", err);
		hi3593_remove(spi);
		return err;
	}

	err = hi3593_create_netdevs(spi);
	if (err) {
		pr_err("avionics-hi3593: Failed to"
		       " register netdevs: %d\n", err);
		hi3593_remove(spi);
		return err;
	}

	return 0;
}

static struct spi_driver hi3593_spi_driver = {
	.driver = {
		.name = "hi3593",
		.of_match_table = hi3593_of_device_id,
	},
	.id_table = hi3593_spi_device_id,
	.probe = hi3593_probe,
	.remove = hi3593_remove,
};
module_spi_driver(hi3593_spi_driver);
