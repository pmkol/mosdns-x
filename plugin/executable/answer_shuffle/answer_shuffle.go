/*
 * Copyright (C) 2020-2026, pmkol
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

package answer_shuffle

import (
	"context"
	"math/rand/v2"

	"github.com/miekg/dns"

	"github.com/pmkol/mosdns-x/coremain"
	"github.com/pmkol/mosdns-x/pkg/executable_seq"
	"github.com/pmkol/mosdns-x/pkg/query_context"
)

const (
	PluginType = "answer_shuffle"
)

func init() {
	coremain.RegNewPersetPluginFunc("_answer_shuffle", func(bp *coremain.BP) (coremain.Plugin, error) {
		return &answerShuffle{BP: bp}, nil
	})
}

var _ coremain.ExecutablePlugin = (*answerShuffle)(nil)

type answerShuffle struct {
	*coremain.BP
}

func (t *answerShuffle) Exec(ctx context.Context, qCtx *query_context.Context, next executable_seq.ExecutableChainNode) error {
	if err := executable_seq.ExecChainNode(ctx, qCtx, next); err != nil {
		return err
	}

	r := qCtx.R()
	if r == nil || len(r.Answer) == 0 {
		return nil
	}

	q := qCtx.Q()
	if len(q.Question) != 1 {
		return nil
	}

	qt := q.Question[0].Qtype
	if qt != dns.TypeA && qt != dns.TypeAAAA {
		return nil
	}

	var aBuf, aaaaBuf [16]int
	var aIdx, aaaaIdx []int

	if len(r.Answer) > 16 {
		aIdx = make([]int, 0, len(r.Answer))
		aaaaIdx = make([]int, 0, len(r.Answer))
	} else {
		aIdx = aBuf[:0]
		aaaaIdx = aaaaBuf[:0]
	}

	for i, rr := range r.Answer {
		switch rr.Header().Rrtype {
		case dns.TypeA:
			aIdx = append(aIdx, i)
		case dns.TypeAAAA:
			aaaaIdx = append(aaaaIdx, i)
		}
	}

	if len(aIdx) > 1 {
		rand.Shuffle(len(aIdx), func(i, j int) {
			r.Answer[aIdx[i]], r.Answer[aIdx[j]] = r.Answer[aIdx[j]], r.Answer[aIdx[i]]
		})
	}

	if len(aaaaIdx) > 1 {
		rand.Shuffle(len(aaaaIdx), func(i, j int) {
			r.Answer[aaaaIdx[i]], r.Answer[aaaaIdx[j]] = r.Answer[aaaaIdx[j]], r.Answer[aaaaIdx[i]]
		})
	}

	return nil
}

func (t *answerShuffle) Shutdown() error {
	return nil
}
