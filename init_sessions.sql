CREATE TABLE IF NOT EXISTS metasploit_sessions (
    id SERIAL PRIMARY KEY,
    session_id VARCHAR(50) NOT NULL,
    task_id VARCHAR(255) REFERENCES tasks(task_id),
    target_ip VARCHAR(255) NOT NULL,
    target_port INTEGER,
    session_type VARCHAR(50) NOT NULL,
    platform VARCHAR(100),
    arch VARCHAR(50),
    status VARCHAR(20) DEFAULT 'active',
    opened_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    closed_at TIMESTAMP,
    last_interaction TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    user_id INTEGER REFERENCES users(id),
    auto_post_exploit_completed BOOLEAN DEFAULT FALSE,
    manual_takeover_enabled BOOLEAN DEFAULT FALSE
);

-- Table pour les actions de post-exploitation
CREATE TABLE IF NOT EXISTS post_exploit_actions (
    id SERIAL PRIMARY KEY,
    session_id INTEGER REFERENCES metasploit_sessions(id),
    action_type VARCHAR(50) NOT NULL,
    command_executed TEXT,
    result_data JSONB,
    raw_output TEXT,
    status VARCHAR(20) DEFAULT 'pending',
    started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP,
    execution_time INTEGER,
    error_message TEXT
);

-- Index pour performances
CREATE INDEX IF NOT EXISTS idx_sessions_task_id ON metasploit_sessions(task_id);
CREATE INDEX IF NOT EXISTS idx_sessions_status ON metasploit_sessions(status);
CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON metasploit_sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_post_exploit_session ON post_exploit_actions(session_id);
CREATE INDEX IF NOT EXISTS idx_post_exploit_status ON post_exploit_actions(status)
