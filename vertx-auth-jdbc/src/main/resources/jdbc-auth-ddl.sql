CREATE TABLE `user` (
  `username` VARCHAR(255) NOT NULL,
  `password` VARCHAR(255) NOT NULL,
  `password_salt` VARCHAR(255) NOT NULL
);

CREATE TABLE `user_roles` (
  `username` VARCHAR(255) NOT NULL,
  `role` VARCHAR(255) NOT NULL
);

CREATE TABLE `roles_perms` (
  `role` VARCHAR(255) NOT NULL,
  `perm` VARCHAR(255) NOT NULL
);

ALTER TABLE user ADD CONSTRAINT `pk_username` PRIMARY KEY (username);
ALTER TABLE user_roles ADD CONSTRAINT `pk_user_roles` PRIMARY KEY (username, role);
ALTER TABLE roles_perms ADD CONSTRAINT `pk_roles_perms` PRIMARY KEY (role, perm);

ALTER TABLE user_roles ADD CONSTRAINT fk_username FOREIGN KEY (username) REFERENCES user(username);
