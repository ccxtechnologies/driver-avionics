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
#include <linux/net.h>
#include "arinc429.h"

MODULE_DESCRIPTION("ARINC429 Socket Driver");
MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Charles Eidsness <charles@ccxtechnologies.com>");

MODULE_ALIAS_NETPROTO(PF_ARINC429);

static __init int arinc429_init(void)
{
	pr_info("Initialising ARINC-429 Socket Driver");
	return 0;
}

static __exit void arinc429_exit(void)
{
	pr_info("Exiting ARINC-429 Socket Driver");
}

module_init(arinc429_init);
module_exit(arinc429_exit);
