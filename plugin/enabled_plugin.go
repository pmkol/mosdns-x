/*
 * Copyright (C) 2020-2022, IrineSistiana
 *
 * This file is part of mosdns.
 *
 * mosdns is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * mosdns is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package plugin

// import all plugins
import (
	_ "github.com/pmkol/mosdns-x/plugin/executable/arbitrary"
	_ "github.com/pmkol/mosdns-x/plugin/executable/blackhole"
	_ "github.com/pmkol/mosdns-x/plugin/executable/bufsize"
	_ "github.com/pmkol/mosdns-x/plugin/executable/cache"
	_ "github.com/pmkol/mosdns-x/plugin/executable/client_limiter"
	_ "github.com/pmkol/mosdns-x/plugin/executable/dual_selector"
	_ "github.com/pmkol/mosdns-x/plugin/executable/ecs"
	_ "github.com/pmkol/mosdns-x/plugin/executable/edns0_filter"
	_ "github.com/pmkol/mosdns-x/plugin/executable/fast_forward"
	_ "github.com/pmkol/mosdns-x/plugin/executable/hosts"
	_ "github.com/pmkol/mosdns-x/plugin/executable/ipset"
	_ "github.com/pmkol/mosdns-x/plugin/executable/marker"
	_ "github.com/pmkol/mosdns-x/plugin/executable/metrics_collector"
	_ "github.com/pmkol/mosdns-x/plugin/executable/misc_optm"
	_ "github.com/pmkol/mosdns-x/plugin/executable/nftset"
	_ "github.com/pmkol/mosdns-x/plugin/executable/padding"
	_ "github.com/pmkol/mosdns-x/plugin/executable/query_summary"
	_ "github.com/pmkol/mosdns-x/plugin/executable/redirect"
	_ "github.com/pmkol/mosdns-x/plugin/executable/reject_any"
	_ "github.com/pmkol/mosdns-x/plugin/executable/reverse_lookup"
	_ "github.com/pmkol/mosdns-x/plugin/executable/sequence"
	_ "github.com/pmkol/mosdns-x/plugin/executable/sleep"
	_ "github.com/pmkol/mosdns-x/plugin/executable/ttl"
	_ "github.com/pmkol/mosdns-x/plugin/matcher/query_matcher"
	_ "github.com/pmkol/mosdns-x/plugin/matcher/response_matcher"
)
