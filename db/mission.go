package db

// Mission profiles: a task's mission (bugbounty / redteam / review-source) selects which
// Main/Planner/Worker/Goals brain runs, with an optional per-task per-agent override.

import "database/sql"

// MissionOfTask returns the task's mission (default "bugbounty" when unset/unknown).
func (d *DB) MissionOfTask(taskID int64) string {
	var m string
	err := d.QueryRow(`SELECT COALESCE(NULLIF(mission,''),'bugbounty') FROM tasks WHERE id=$1`, taskID).Scan(&m)
	if err != nil || m == "" {
		return "bugbounty"
	}
	return m
}

// SetTaskMission sets a task's mission (ignored when empty so the default stays).
func (d *DB) SetTaskMission(taskID int64, mission string) error {
	if mission == "" {
		return nil
	}
	_, err := d.Exec(`UPDATE tasks SET mission=$2 WHERE id=$1`, taskID, mission)
	return err
}

// MissionPrompt returns the stored prompt for (mission, agentKey) if present.
func (d *DB) MissionPrompt(mission, agentKey string) (string, bool) {
	var b string
	err := d.QueryRow(`SELECT body FROM mission_prompts WHERE mission=$1 AND agent_key=$2`, mission, agentKey).Scan(&b)
	if err != nil || b == "" {
		return "", false
	}
	return b, true
}

// TaskAgentPrompt returns the per-task override of one agent's brain if present.
func (d *DB) TaskAgentPrompt(taskID int64, agentKey string) (string, bool) {
	var b string
	err := d.QueryRow(`SELECT body FROM task_agent_prompt WHERE task_id=$1 AND agent_key=$2`, taskID, agentKey).Scan(&b)
	if err != nil || b == "" {
		return "", false
	}
	return b, true
}

// SetMissionPrompt upserts a mission's agent brain.
func (d *DB) SetMissionPrompt(mission, agentKey, body string) error {
	_, err := d.Exec(`INSERT INTO mission_prompts(mission,agent_key,body) VALUES($1,$2,$3)
		ON CONFLICT (mission,agent_key) DO UPDATE SET body=excluded.body, updated_at=now()`, mission, agentKey, body)
	return err
}

// MissionPromptExists reports whether a (mission, agentKey) row is already seeded.
func (d *DB) MissionPromptExists(mission, agentKey string) bool {
	var one int
	err := d.QueryRow(`SELECT 1 FROM mission_prompts WHERE mission=$1 AND agent_key=$2`, mission, agentKey).Scan(&one)
	return err == nil
}

// MissionPromptRow is one editable mission brain (for the Agent-page mission tabs).
type MissionPromptRow struct {
	Mission  string `json:"mission"`
	AgentKey string `json:"agent_key"`
	Body     string `json:"body"`
}

// ListMissionPrompts returns all mission brains for the UI.
func (d *DB) ListMissionPrompts() ([]MissionPromptRow, error) {
	rows, err := d.Query(`SELECT mission, agent_key, body FROM mission_prompts ORDER BY mission, agent_key`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []MissionPromptRow
	for rows.Next() {
		var r MissionPromptRow
		if err := rows.Scan(&r.Mission, &r.AgentKey, &r.Body); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// SetTaskAgentPrompt upserts (or clears when body=="") a per-task agent override.
func (d *DB) SetTaskAgentPrompt(taskID int64, agentKey, body string) error {
	if body == "" {
		_, err := d.Exec(`DELETE FROM task_agent_prompt WHERE task_id=$1 AND agent_key=$2`, taskID, agentKey)
		return err
	}
	_, err := d.Exec(`INSERT INTO task_agent_prompt(task_id,agent_key,body) VALUES($1,$2,$3)
		ON CONFLICT (task_id,agent_key) DO UPDATE SET body=excluded.body`, taskID, agentKey, body)
	return err
}

var _ = sql.ErrNoRows
