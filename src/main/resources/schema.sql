CREATE TABLE spaces(
    space_id INT PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    owner VARCHAR(30) NOT NULL
);
CREATE SEQUENCE space_id_seq;

CREATE TABLE messages(
    msg_id INT PRIMARY KEY,
    space_id INT NOT NULL REFERENCES spaces(space_id),
    author VARCHAR(30) NOT NULL,
    msg_time TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    msg_text VARCHAR(1024) NOT NULL
);
CREATE SEQUENCE msg_id_seq;
CREATE INDEX msg_timestamp_idx ON messages(msg_time);
CREATE UNIQUE INDEX space_name_idx ON spaces(name);

-- privileges
CREATE USER IF NOT EXISTS natter_api_user PASSWORD 'password';
GRANT SELECT, INSERT ON spaces, messages TO natter_api_user;