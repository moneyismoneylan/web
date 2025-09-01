DROP TABLE IF EXISTS users;

CREATE TABLE users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  description TEXT
);

INSERT INTO users (name, description) VALUES ('admin', 'The administrator');
INSERT INTO users (name, description) VALUES ('jules', 'A friendly agent');
INSERT INTO users (name, description) VALUES ('user123', 'A standard user account');
