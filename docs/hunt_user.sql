-- Read-only principal for LLM-generated hunt queries.
-- readonly=1 in a settings profile cannot be overridden by the query itself.
CREATE SETTINGS PROFILE IF NOT EXISTS hunt_profile SETTINGS readonly = 1 CONST, max_execution_time = 10, max_result_rows = 10000;
CREATE USER IF NOT EXISTS hunt IDENTIFIED BY 'hunt-localdev' SETTINGS PROFILE 'hunt_profile';
GRANT SELECT ON default.agent_events TO hunt;
GRANT SELECT ON default.agent_controls TO hunt;
