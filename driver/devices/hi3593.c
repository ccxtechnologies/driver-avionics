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

#include "avionics.h"
#include "avionics-device.h"

MODULE_DESCRIPTION("HOLT Hi-3593 ARINC-429 Driver");
MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Charles Eidsness <charles@ccxtechnologies.com>");
MODULE_VERSION("1.0.0");

#define HI3593_MTU	(32*sizeof(__u32)) /* 32 word FIFO */

#define HI3593_OPCODE_RESET		0x04
#define HI3593_OPCODE_RD_TX_STATUS	0x80
#define HI3593_OPCODE_RD_ALCK		0xd4
#define HI3593_OPCODE_WR_ALCK		0x38

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

#define HI3593_PRIORITY_LABEL1	0x08
#define HI3593_PRIORITY_LABEL2	0x10
#define HI3593_PRIORITY_LABEL3	0x20

#define HI3593_NUM_TX	1
#define HI3593_NUM_RX	2

struct hi3593 {
	struct net_device *rx[HI3593_NUM_RX];
	struct net_device *tx[HI3593_NUM_TX];
	int reset_gpio;
	int irq[2];
	__u32 aclk;
	struct mutex lock;
};

struct hi3593_priv {
	struct net_device *dev;
	struct spi_device *spi;
	struct sk_buff_head skbq;
	int tx_index;
	int rx_index;
	struct mutex *lock;
	struct workqueue_struct *wq;
	struct work_struct worker;
	int irq;
	__u8 even_parity;
	__u8 check_parity;
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

	mutex_lock(priv->lock);

	status = hi3593_get_cntrl(priv);
	if (status < 0) {
		pr_err("avionics-hi3593: Failed to read control: %d\n", status);
		mutex_unlock(priv->lock);
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
		mutex_unlock(priv->lock);
		return -EINVAL;
	}

	wr_cmd[1] = (status&(~mask)) | (value&mask);
	err = spi_write(priv->spi, wr_cmd, sizeof(wr_cmd));
	if (err < 0) {
		pr_err("avionics-hi3593: Failed to set control\n");
		mutex_unlock(priv->lock);
		return err;
	}

	status = hi3593_get_cntrl(priv);
	if (status < 0) {
		pr_err("avionics-hi3593: Failed to read control: %d\n", status);
		mutex_unlock(priv->lock);
		return -ENODEV;
	}

	if ((status&mask) != (value&mask)) {
		pr_err("avionics-hi3593: Failed to set"
		       " control to 0x%x & 0x%x : 0x%x\n", value, mask, status);
		mutex_unlock(priv->lock);
		return -ENODEV;
	}

	mutex_unlock(priv->lock);
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
		pr_err("avionics-hi3593: Failed to get rate: %d\n", status);
	} else if(status&0x0001) {
		rate->rate_hz = 12500;
	} else {
		rate->rate_hz = 100000;
	}
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
		pr_err("avionics-hi3593: Failed to get rx cntrl: %d\n", status);
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
		pr_err("avionics-hi3593: Failed to get tx cntrl: %d\n", status);
	} else {
		config->flags = status;
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

	err = hi3593_set_cntrl(priv, config->flags, 0x5c);
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
		pr_err("avionics-hi3593: MTU must be %d.\n", HI3593_MTU);
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
		pr_err("avionics-hi3593: Failed to disable driver\n");
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
	flush_workqueue(priv->wq);

	err = hi3593_set_cntrl(priv, AVIONICS_ARINC429TX_HIZ,
			       AVIONICS_ARINC429TX_HIZ);
	if (err < 0) {
		pr_err("avionics-hi3593: Failed to disable driver\n");
		return err;
	}

	return 0;
}

static void hi3593_rx_worker(struct work_struct *work)
{
	struct net_device *dev;
	struct net_device_stats *stats;
	struct hi3593_priv *priv;
	struct sk_buff *skb;
	__u8 status_cmd, rd_cmd, data[32*sizeof(__u32)];
	__u8 pl_cmd[3], pl_rd, pl[3];
	const __u8 pl_bits[3] = {HI3593_PRIORITY_LABEL1,
		HI3593_PRIORITY_LABEL2, HI3593_PRIORITY_LABEL3};
	ssize_t status;
	int err, i, cnt;

	priv = container_of(work, struct hi3593_priv, worker);
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

	mutex_lock(priv->lock);

	status = spi_w8r8(priv->spi, status_cmd);
	if (status < 0) {
		pr_err("avionics-hi3593: Failed to read status\n");
		mutex_unlock(priv->lock);
		return;
	}

	if (status & HI3593_FIFO_FULL) {
		stats->rx_errors++;
		stats->rx_fifo_errors++;
	}

	if (status & (pl_bits[0] | pl_bits[1] | pl_bits[2])) {
		err = spi_write_then_read(priv->spi, &pl_rd, sizeof(pl_rd),
					  pl, sizeof(pl));
		if (unlikely(err)) {
			pr_err("avionics-hi3593: Failed to"
			       " read priority labels\n");
			mutex_unlock(priv->lock);
			return;
		}
	}

	for (i = 0; i < 3; i++) {
		if (status & pl_bits[i]) {
			data[3] = pl[2-i];
			err = spi_write_then_read(priv->spi, &pl_cmd[i],
						  sizeof(pl_cmd[0]), data,
						  sizeof(__u32)-1);
			if (unlikely(err)) {
				pr_err("avionics-hi3593: Failed to"
				       " read priority label\n");
				mutex_unlock(priv->lock);
				return;
			}

			if(!priv->check_parity ||
			   (priv->even_parity && (0x80&data[0])) ||
			   ((0x80&data[0]) == 0x00)) {
				if (priv->check_parity && priv->even_parity) {
					data[0] &= 0x7f;
				}

				skb = avionics_device_alloc_skb(dev,
								sizeof(__u32));
				if (unlikely(!skb)) {
					pr_err("avionics-lb: Failed to"
					       " allocate RX buffer\n");
					mutex_unlock(priv->lock);
					return;
				}

				skb_copy_to_linear_data(skb, data,
							sizeof(__u32));
				stats->rx_packets++;
				stats->rx_bytes += skb->len;
				netif_rx_ni(skb);
			} else {
				stats->rx_errors++;
				stats->rx_crc_errors++;
			}
		}
	}

	cnt = 0;
	if (status & HI3593_FIFO_HALF) {
		for (i = 0; i < HI3593_MTU; i += sizeof(__u32)) {

			err = spi_write_then_read(priv->spi, &rd_cmd,
						  sizeof(rd_cmd),
						  &data[cnt],
						  sizeof(__u32));
			if (unlikely(err)) {
				pr_err("avionics-hi3593: Failed to"
				       " read from fifo\n");
				mutex_unlock(priv->lock);
				return;
			}

			if(!priv->check_parity ||
			   (priv->even_parity && (0x80&data[cnt])) ||
			   ((0x80&data[cnt]) == 0x00)) {
				cnt += sizeof(__u32);
				if (priv->check_parity && priv->even_parity) {
					data[cnt] &= 0x7f;
				}
			} else {
				stats->rx_errors++;
				stats->rx_crc_errors++;
			}

			status = spi_w8r8(priv->spi, status_cmd);
			if (unlikely(status < 0)) {
				pr_err("avionics-hi3593: Failed to"
				       " read status\n");
				mutex_unlock(priv->lock);
				return;
			}

			if(status & HI3593_FIFO_EMPTY) {
				break;
			}
		}

		if (cnt) {
			skb = avionics_device_alloc_skb(dev, cnt);
			if (unlikely(!skb)) {
				pr_err("avionics-lb: Failed to"
				       " allocate RX buffer\n");
				mutex_unlock(priv->lock);
				return;
			}

			skb_copy_to_linear_data(skb, data, cnt);

			stats->rx_packets++;
			stats->rx_bytes += skb->len;

			netif_rx_ni(skb);
		}
	}

	mutex_unlock(priv->lock);

}

static irqreturn_t hi3593_rx_irq(int irq, void *data)
{
	struct hi3593_priv *priv = data;

	queue_work(priv->wq, &priv->worker);
	return IRQ_HANDLED;
}

static void hi3593_tx_worker(struct work_struct *work)
{
	struct net_device *dev;
	struct net_device_stats *stats;
	struct hi3593_priv *priv;
	struct sk_buff *skb;
	__u8 rd_cmd, wr_cmd[5], send_cmd;
	ssize_t status;
	int err, i;

	priv = container_of(work, struct hi3593_priv, worker);
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

	mutex_lock(priv->lock);

	status = spi_w8r8(priv->spi, rd_cmd);
	if (status < 0) {
		pr_err("avionics-hi3593: Failed to read status\n");
		mutex_unlock(priv->lock);
		return;
	}

	if ((status & HI3593_FIFO_FULL) ||
	    ((skb->len > (1*sizeof(__u32))) &&
	     (status & HI3593_FIFO_HALF)) ||
	    ((skb->len > (16*sizeof(__u32))) &&
	     !(status & HI3593_FIFO_EMPTY))) {
		/* TODO: Come up with a better dropping algo. */
		kfree_skb(skb);
		stats->tx_dropped++;
		mutex_unlock(priv->lock);
		return;
	}

	wr_cmd[0] = HI3593_OPCODE_WR_TX_FIFO;
	for (i = 0; i < skb->len; i = i + sizeof(__u32)) {
		memcpy(&wr_cmd[1], &skb->data[i], sizeof(__u32));
		err = spi_write(priv->spi, &wr_cmd, sizeof(wr_cmd));
		if (err < 0) {
			pr_err("avionics-hi3593: Failed to load fifo\n");
			mutex_unlock(priv->lock);
			return;
		}
	}

	send_cmd = HI3593_OPCODE_WR_TX_SEND;
	err = spi_write(priv->spi, &send_cmd, sizeof(send_cmd));
	if (err < 0) {
		pr_err("avionics-hi3593: Failed to send transmit command\n");
		mutex_unlock(priv->lock);
		return;
	}

	mutex_unlock(priv->lock);

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

	if (unlikely(skb->len % 4)) {
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
	queue_work(priv->wq, &priv->worker);

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

	return 0;
}

static int hi3593_reset(struct spi_device *spi)
{
	struct hi3593 *hi3593 = spi_get_drvdata(spi);
	__u8 opcode;
	ssize_t status;
	int err;

	if (hi3593->reset_gpio <= 0 ) {
		pr_err("avionics-hi3593: Reset GPIO Reset missing/malformed,"
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
		usleep_range(100, 150);
		gpio_set_value(hi3593->reset_gpio, 0);
	}

	status = spi_w8r8(spi, HI3593_OPCODE_RD_TX_STATUS);
	if (status != 0x01) {
		pr_err("avionics-hi3593: TX FIFO is not cleared: %x\n", status);
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
		cmd[1] = hi3593->aclk/2000000;
	}

	err = spi_write(spi, &cmd, sizeof(cmd));
	if (err < 0) {
		pr_err("avionics-hi3593: Failed to send aclk set command\n");
		return err;
	}

	status = spi_w8r8(spi, HI3593_OPCODE_RD_ALCK);
	if (status != cmd[1]) {
		pr_err("avionics-hi3593: ALCK not set to 0x%x: 0x%x\n",
		       cmd[1], status);
		return -ENODEV;
	}

	pr_info("avionics-hi3593: ALCK set to 0x%x\n", status);

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
		priv->wq = alloc_workqueue("%s", WQ_FREEZABLE | WQ_MEM_RECLAIM,
					   0, hi3593->tx[i]->name);
		if (!priv->wq) {
			pr_err("avionics-hi3593: Failed to allocate"
			       " tx work-queue %d\n", i);
			return -ENOMEM;
		}

		INIT_WORK(&priv->worker, hi3593_tx_worker);

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
		skb_queue_head_init(&priv->skbq);
		priv->wq = alloc_workqueue("%s", WQ_FREEZABLE | WQ_MEM_RECLAIM,
					   0, hi3593->rx[i]->name);
		if (!priv->wq) {
			pr_err("avionics-hi3593: Failed to allocate"
			       " rx work-queue %d\n", i);
			return -ENOMEM;
		}

		INIT_WORK(&priv->worker, hi3593_rx_worker);

		err = request_irq(hi3593->irq[i], hi3593_rx_irq,
				  IRQF_TRIGGER_RISING | IRQF_ONESHOT,
				  hi3593->rx[i]->name, priv);
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

static int hi3593_remove(struct spi_device *spi)
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
				destroy_workqueue(priv->wq);
			}
			avionics_device_unregister(hi3593->tx[i]);
			avionics_device_free(hi3593->tx[i]);
			hi3593->tx[i] = NULL;
		}
	}

	for (i = 0; i < HI3593_NUM_RX; i++) {
		if (hi3593->rx[i]) {
			priv = avionics_device_priv(hi3593->rx[i]);
			if (priv) {
				skb_queue_purge(&priv->skbq);
				destroy_workqueue(priv->wq);
				if (priv->irq) {
					free_irq(priv->irq, priv);
				}
			}
			avionics_device_unregister(hi3593->rx[i]);
			avionics_device_free(hi3593->rx[i]);
			hi3593->rx[i] = 0;
		}
	}

	if (hi3593->reset_gpio > 0) {
		gpio_set_value(hi3593->reset_gpio, 1);
		gpio_free(hi3593->reset_gpio);
		hi3593->reset_gpio = 0;
	}

	return 0;
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
