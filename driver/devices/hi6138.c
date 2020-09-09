/*
 * Copyright (C), 2020 CCX Technologies
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

#include "avionics.h"
#include "avionics-device.h"

MODULE_DESCRIPTION("HOLT Hi-6138 MIL-1553 Driver");
MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Charles Eidsness <charles@ccxtechnologies.com>");
MODULE_VERSION("1.0.0");

struct hi6138 {
	struct net_device *bm;
	struct workqueue_struct *wq;
	int reset_gpio;
	int irq;
	__u32 aclk;
	struct mutex lock;
	atomic_t bm_enabled;
};

struct hi6138_priv {
	struct net_device *dev;
	struct spi_device *spi;
	struct sk_buff_head skbq;
	struct mutex *lock;
	struct workqueue_struct *wq;
	struct delayed_work worker;
	int irq;
	atomic_t *bm_enabled;
};

static void hi6138_get_mil1553bm(struct avionics_mil1553bm *config,
		       const struct net_device *dev)
{
	struct hi6138_priv *priv;

	priv = avionics_device_priv(dev);
	if (!priv) {
		pr_err("avionics-hi6138-bm: Failed to get private data\n");
		return;
	}

	/* TODO: add get settings here */

}

static int hi6138_set_mil1553bm(struct avionics_mil1553bm *config,
				 const struct net_device *dev)
{
	struct hi6138_priv *priv;

	priv = avionics_device_priv(dev);
	if (!priv) {
		pr_err("avionics-hi6138-bm: Failed to get private data\n");
		return -ENODEV;
	}

	/* TODO: add set settings here */

	return 0;
}

static struct avionics_ops hi6138_mil553bm_ops = {
	.name = "mil1553bm%d",
	.get_mil1553bm = hi6138_get_mil1553bm,
	.set_mil1553bm = hi6138_set_mil1553bm,
};

static int hi6138_bm_open(struct net_device *dev)
{
	struct hi6138_priv *priv;

	priv = avionics_device_priv(dev);
	if (!priv) {
		pr_err("avionics-hi6138-bm: Failed to get private data\n");
		return -EINVAL;
	}

	if (atomic_read(priv->bm_enabled)) {
		pr_err("avionics-hi6138-bm: Bus Monitor already running\n");
		return 0;
	}

	atomic_set(priv->bm_enabled, 1);
	enable_irq(priv->irq);

	return 0;
}

static int hi6138_bm_stop(struct net_device *dev)
{
	struct hi6138_priv *priv;

	pr_warn("avionics-hi6138-bm: Disabling Receiver\n");

	netif_stop_queue(dev);

	priv = avionics_device_priv(dev);
	if (!priv) {
		pr_err("avionics-hi6138-bm: Failed to get private data\n");
		return -EINVAL;
	}

	atomic_set(priv->bm_enabled, 0);
	disable_irq(priv->irq);

	return 0;
}

static void hi6138_bm_worker(struct work_struct *work)
{
	struct net_device *dev;
	struct net_device_stats *stats;
	struct hi6138_priv *priv;

	priv = container_of((struct delayed_work*)work,
			    struct hi6138_priv, worker);
	dev = priv->dev;
	stats = &dev->stats;

	priv = avionics_device_priv(dev);
	if (!priv) {
		pr_err("avionics-hi6138: Failed to get private data\n");
		return;
	}

	mutex_lock(priv->lock);

	/* TODO: Add IRQ service

done: */
	mutex_unlock(priv->lock);
	enable_irq(priv->irq);

}

static irqreturn_t hi6138_irq(int irq, void *data)
{
	struct hi6138_priv *priv = data;

	if (unlikely(irq != priv->irq)) {
		pr_err("avionics-hi6138: Unexpected irq %d\n", irq);
		return IRQ_HANDLED;
	}

	disable_irq_nosync(priv->irq);

	if (atomic_read(priv->bm_enabled)) {
		queue_delayed_work(priv->wq, &priv->worker, 10); /* TODO: Caluclate a propper delay */
	}

	return IRQ_HANDLED;
}

static const struct net_device_ops hi6138_bm_netdev_ops = {
	.ndo_open = hi6138_bm_open,
	.ndo_stop = hi6138_bm_stop,
};

static const struct of_device_id hi6138_of_device_id[] = {
	{ .compatible	= "holt,hi6138" },
	{}
};
MODULE_DEVICE_TABLE(of, hi6138_of_device_id);

static const struct spi_device_id hi6138_spi_device_id[] = {
	{
		.name		= "hi6138",
		.driver_data	= (kernel_ulong_t)0,
	},
	{}
};
MODULE_DEVICE_TABLE(spi, hi6138_spi_device_id);

static int hi6138_get_config(struct spi_device *spi)
{
	struct hi6138 *hi6138 = spi_get_drvdata(spi);
	struct device *dev = &spi->dev;
	int err;

	hi6138->reset_gpio = of_get_named_gpio(dev->of_node, "reset-gpio", 0);
	if (hi6138->reset_gpio > 0 ) {
		if (!gpio_is_valid(hi6138->reset_gpio)) {
			pr_err("avionics-hi6138: Reset GPIO is not valid\n");
			return -EINVAL;
		}

		err = devm_gpio_request_one(&spi->dev, hi6138->reset_gpio,
					    GPIOF_OUT_INIT_LOW, "reset");
		if (err) {
			pr_err("avionics-hi6138: Failed to"
			       " register Reset GPIO\n");
			return err;
		}
	}

	hi6138->irq = irq_of_parse_and_map(dev->of_node, 0);
	if (hi6138->irq < 0) {
		pr_err("avionics-hi6138: Failed to get irq: %d\n",
		       hi6138->irq);
		return hi6138->irq;
	}

	return 0;
}

static int hi6138_reset(struct spi_device *spi)
{
	struct hi6138 *hi6138 = spi_get_drvdata(spi);

	gpio_set_value(hi6138->reset_gpio, 0);
	usleep_range(100, 150);
	gpio_set_value(hi6138->reset_gpio, 1);

	/* TODO: Add id check */

	pr_info("avionics-hi6138: Device up\n");
	return 0;
}

static struct avionics_mil1553bm avionics_mil1553bm_default = {
	.flags = 0,
};

static int hi6138_create_netdevs(struct spi_device *spi)
{
	struct hi6138 *hi6138 = spi_get_drvdata(spi);
	struct hi6138_priv *priv;
	int err;

	hi6138->wq = alloc_workqueue("hi6138", WQ_HIGHPRI, 0);
	if (!hi6138->wq) {
		pr_err("avionics-hi6138: Failed to allocate work-queue\n");
		return -ENOMEM;
	}

	hi6138->bm = avionics_device_alloc(sizeof(*priv),
					   &hi6138_mil553bm_ops);

	if (!hi6138->bm ) {
		pr_err("avionics-hi6138: Failed to allocate"
		       " Bus Monitor netdev\n");
		return -ENOMEM;
	}

	hi6138->bm->netdev_ops = &hi6138_bm_netdev_ops;
	priv = avionics_device_priv(hi6138->bm);

	if (!priv) {
		pr_err("avionics-hi6138: Failed to get private data"
		       " for Bus Monitor\n");
		return -EINVAL;
	}
	priv->dev = hi6138->bm;
	priv->spi = spi;
	priv->lock = &hi6138->lock;
	priv->bm_enabled = &hi6138->bm_enabled;
	skb_queue_head_init(&priv->skbq);
	priv->wq = hi6138->wq;

	INIT_DELAYED_WORK(&priv->worker, hi6138_bm_worker);

	err = hi6138_set_mil1553bm(&avionics_mil1553bm_default,
				    hi6138->bm);
	if (err) {
		pr_err("avionics-hi6138: Failed to set Bus Monitor"
		       " default settings\n");
		return -EINVAL;
	}

	err = avionics_device_register(hi6138->bm);
	if (err) {
		pr_err("avionics-hi6138: Failed to register"
		       " Bus Monitor netdev\n");
		return -EINVAL;
	}

	err = request_irq(hi6138->irq, hi6138_irq,
			  IRQF_TRIGGER_FALLING | IRQF_ONESHOT,
			  "hi6138", priv);
	if (err) {
		pr_err("avionics-hi6138: Failed to register"
		       " irq %d\n", hi6138->irq);
		return -EINVAL;
	}
	priv->irq = hi6138->irq;
	disable_irq_nosync(priv->irq);

	return 0;
}

static int hi6138_remove(struct spi_device *spi)
{
	struct hi6138 *hi6138 = spi_get_drvdata(spi);
	struct hi6138_priv *priv;

	pr_info("avionics-hi6138: Removing Device\n");

	if (hi6138->bm) {
		priv = avionics_device_priv(hi6138->bm);
		if (priv) {
			skb_queue_purge(&priv->skbq);
			cancel_delayed_work_sync(&priv->worker);
		}
		avionics_device_unregister(hi6138->bm);
		avionics_device_free(hi6138->bm);
		hi6138->bm = NULL;
	}

	if (hi6138->reset_gpio > 0) {
		gpio_set_value(hi6138->reset_gpio, 1);
		gpio_free(hi6138->reset_gpio);
		hi6138->reset_gpio = 0;
	}

	if (hi6138->wq) {
		flush_scheduled_work();
		flush_workqueue(hi6138->wq);
		destroy_workqueue(hi6138->wq);
	}

	return 0;
}

static int hi6138_probe(struct spi_device *spi)
{
	struct hi6138 *hi6138;
	struct device *dev = &spi->dev;
	int err;

	pr_info("avionics-hi6138: Adding Device\n");

	hi6138 = devm_kzalloc(dev, sizeof(*hi6138), GFP_KERNEL);
	if (!hi6138) {
		pr_err("avionics-hi6138: Failed to allocate hi6138 memory\n");
		return -ENOMEM;
	}
	spi_set_drvdata(spi, hi6138);
	mutex_init(&hi6138->lock);
	atomic_set(&hi6138->bm_enabled, 0);

	err = hi6138_get_config(spi);
	if (err) {
		pr_err("avionics-hi6138: Failed to get system configuration"
		       " from dts file: %d\n",err);
		hi6138_remove(spi);
		return err;
	}

	err = hi6138_reset(spi);
	if (err) {
		pr_err("avionics-hi6138: Failed to bring device"
		       " out of reset: %d\n",err);
		hi6138_remove(spi);
		return err;
	}

	err = hi6138_create_netdevs(spi);
	if (err) {
		pr_err("avionics-hi6138: Failed to"
		       " register netdevs: %d\n", err);
		hi6138_remove(spi);
		return err;
	}

	return 0;
}

static struct spi_driver hi6138_spi_driver = {
	.driver = {
		.name = "hi6138",
		.of_match_table = hi6138_of_device_id,
	},
	.id_table = hi6138_spi_device_id,
	.probe = hi6138_probe,
	.remove = hi6138_remove,
};
module_spi_driver(hi6138_spi_driver);
