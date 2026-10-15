package workflow

import (
	"sort"
)

// TopologicalOrder runs Kahn's algorithm. The ready list is repeatedly
// re-sorted by original step index so the order is deterministic and matches
// the Python engine.
func TopologicalOrder(steps []*Step) ([]*Step, error) {
	byID := map[string]*Step{}
	for _, s := range steps {
		byID[s.ID] = s
	}
	remaining := map[string][]string{}
	indeg := map[string]int{}
	for _, s := range steps {
		var deps []string
		for _, d := range s.DependsOn {
			if _, ok := byID[d]; !ok {
				return nil, werrf("Step '%s' depends on unknown step(s): %s", s.ID, d)
			}
			deps = append(deps, d)
		}
		remaining[s.ID] = deps
		indeg[s.ID] = len(deps)
	}
	var ready []*Step
	for _, s := range steps {
		if indeg[s.ID] == 0 {
			ready = append(ready, s)
		}
	}
	var order []*Step
	for len(ready) > 0 {
		sort.Slice(ready, func(i, j int) bool { return ready[i].Index < ready[j].Index })
		s := ready[0]
		ready = ready[1:]
		order = append(order, s)
		for _, t := range steps {
			if remaining[t.ID] == nil {
				continue
			}
			for i, d := range remaining[t.ID] {
				if d == s.ID {
					remaining[t.ID] = append(remaining[t.ID][:i], remaining[t.ID][i+1:]...)
					indeg[t.ID]--
					if indeg[t.ID] == 0 {
						ready = append(ready, t)
					}
					break
				}
			}
		}
	}
	if len(order) != len(steps) {
		return nil, werrf("Dependency cycle detected")
	}
	return order, nil
}

// ExecutionLevels groups steps into BFS levels: level = max(level(dep)) + 1.
// Levels run sequentially; steps within a level are independent.
func ExecutionLevels(steps []*Step) ([][]*Step, error) {
	order, err := TopologicalOrder(steps)
	if err != nil {
		return nil, err
	}
	level := map[string]int{}
	var maxLevel int
	for _, s := range order {
		l := 0
		for _, d := range s.DependsOn {
			if level[d]+1 > l {
				l = level[d] + 1
			}
		}
		level[s.ID] = l
		if l > maxLevel {
			maxLevel = l
		}
	}
	levels := make([][]*Step, maxLevel+1)
	for _, s := range order {
		levels[level[s.ID]] = append(levels[level[s.ID]], s)
	}
	return levels, nil
}
