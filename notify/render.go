package notify

import (
	"strings"
	"unicode/utf8"
)

const ellipsis = "…"

// TruncateBytes truncates s to at most max bytes, guaranteeing the result is valid UTF-8 and
// does not cut a character in half.
//
// Why we must cut on a character boundary: the WeCom group bot's markdown has a hard 4096-**byte**
// limit (not a character count), while a Chinese character is 3 bytes. Slicing directly by byte
// would cut a Chinese character in two, producing invalid UTF-8 — the platform then either rejects
// the whole message or shows garbled boxes. The approach here is to first back up from the budget
// position to the nearest rune start byte (utf8.RuneStart detects continuation bytes 0b10xxxxxx).
//
// max<=0 means no limit. An ellipsis is appended after truncation, unless max is too small to fit the ellipsis.
func TruncateBytes(s string, max int) string {
	if max <= 0 || len(s) <= max {
		return s
	}
	budget := max - len(ellipsis)
	suffix := ellipsis
	if budget < 0 {
		// max is shorter than the ellipsis itself: drop the ellipsis and truncate plainly, to avoid the result exceeding max.
		budget = max
		suffix = ""
	}
	cut := budget
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + suffix
}

// OneLine collapses multi-line text into a single line: it folds all whitespace, then truncates by character count.
// Used for the title line of IM messages — summaries often contain line breaks, and stuffing them straight into a table/title breaks the layout.
// max<=0 means no length limit.
func OneLine(s string, max int) string {
	s = strings.Join(strings.Fields(s), " ")
	return TruncateRunes(s, max)
}

// TruncateRunes truncates s to at most max characters (not bytes), appending an ellipsis when it exceeds.
// max<=0 means no limit.
//
// The difference from TruncateBytes is the platform's unit: WeCom limits by bytes, Telegram limits
// by character count. Using the wrong unit does not raise an error, it just cuts the message far
// shorter than expected (a Chinese character = 3 bytes, so cutting at 4096 bytes leaves only about
// 1365 characters), so both functions must be kept and chosen per channel.
func TruncateRunes(s string, max int) string {
	if max <= 0 {
		return s
	}
	runes := []rune(s)
	if len(runes) <= max {
		return s
	}
	if max <= 1 {
		return string(runes[:max])
	}
	return string(runes[:max-1]) + ellipsis
}

// TruncateHTML truncates an HTML fragment by character count, guaranteeing it never produces a half-cut tag.
//
// Truncating HTML by characters directly can cut out a broken tag like `<a href="htt`, and the
// platform parser either errors and rejects the whole message or swallows the following body as an
// attribute value. The approach here: truncate by characters first, then check whether the tail has
// an unclosed `<`, and if so back up to before it.
//
// We do not balance tags (completing a </b> and the like): Telegram's HTML parser auto-closes
// unclosed tags, and implementing balancing ourselves would mean handling quotes in attributes,
// comments, and self-closing tags — a complexity out of proportion to the benefit.
func TruncateHTML(s string, max int) string {
	if max <= 0 || len([]rune(s)) <= max {
		return s
	}
	cut := TruncateRunes(s, max)
	// If the tail is a fragment starting with `<` (the last `<` has no `>` after it), back up to before the `<`.
	if lt := strings.LastIndex(cut, "<"); lt >= 0 && !strings.Contains(cut[lt:], ">") {
		cut = cut[:lt]
	}
	// If the tail is a cut-off HTML entity (e.g. `&amp;` cut down to `&amp`), back up as well.
	// An entity fragment can get the **whole message** rejected by a parser that only accepts entities —
	// a digest message over the length limit is common in the first place, and it is not worth losing
	// the whole notification over it.
	if amp := strings.LastIndex(cut, "&"); amp >= 0 && !strings.Contains(cut[amp:], ";") {
		cut = cut[:amp]
	}
	return cut
}

// packItemCount computes how many items fit **completely** within the budget, so a digest message packs by whole items.
//
// Why pack by whole items instead of rendering the full text and then truncating: truncation would
// make the latter items vanish into thin air, while their delivery records still get marked as
// delivered — invisible in the message and invisible in the delivery history, and the vulnerability
// is simply gone. After packing by whole items, the ones that do not fit stay in the store as the
// next batch, and the kept count the caller receives is the number of items this message actually delivered.
//
// Parameters: maxSize<=0 means no limit; reserve is the amount set aside for the message
// header/footer; size does the measuring (platforms differ: WeCom/DingTalk by bytes, Telegram by
// character count — using the wrong unit does not raise an error, it just squeezes a Chinese message
// far below the limit); render renders item idx into its actual text — its length varies by content
// and cannot be estimated.
//
// Returns at least 1 (as long as there are items). Even when a single item is extremely long it must
// still be sent, with the caller's final truncation as the backstop; otherwise one oversized
// vulnerability would jam the whole batch in place forever.
func packItemCount(items []Item, maxSize, reserve int, footer string, size func(string) int, render func(Item, int) string) int {
	if maxSize <= 0 {
		return len(items)
	}
	budget := maxSize - reserve - size(footer)
	if budget < 0 {
		budget = 0
	}
	used := 0
	for i, it := range items {
		used += size(render(it, i))
		if used > budget && i > 0 {
			return i
		}
	}
	return len(items)
}

// byteSize / runeSize are packItemCount's two measuring units, named so the call sites do not have
// bare func(s string) int closures, which would make it hard to tell at a glance which unit is in use.
func byteSize(s string) int { return len(s) }
func runeSize(s string) int { return utf8.RuneCountInString(s) }

// assetLine renders the asset list into a single line of display text, omitting the rest and noting the total when there are more than limit.
// A single vulnerability may anchor dozens of assets, and listing them all would overflow the message.
func assetLine(assets []string, limit int) string {
	if len(assets) == 0 {
		return ""
	}
	if limit <= 0 || len(assets) <= limit {
		return strings.Join(assets, ", ")
	}
	return strings.Join(assets[:limit], ", ") + " and " + itoa(len(assets)) + " total"
}

// itoa is a short alias for strconv.Itoa, used only to concatenate display text, avoiding import strconv everywhere.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
