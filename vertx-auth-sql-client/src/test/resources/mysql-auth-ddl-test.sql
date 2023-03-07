CREATE TABLE `users`
(
  username VARCHAR(255) NOT NULL,
  password VARCHAR(255) NOT NULL
);

CREATE TABLE `users_roles`
(
  username VARCHAR(255) NOT NULL,
  role     VARCHAR(255) NOT NULL
);

CREATE TABLE `roles_perms`
(
  role VARCHAR(255) NOT NULL,
  perm VARCHAR(255) NOT NULL
);

ALTER TABLE `users`
  ADD CONSTRAINT pk_username PRIMARY KEY (username);
ALTER TABLE `users_roles`
  ADD CONSTRAINT pk_users_roles PRIMARY KEY (username, role);
ALTER TABLE `roles_perms`
  ADD CONSTRAINT pk_roles_perms PRIMARY KEY (role, perm);

ALTER TABLE users_roles
  ADD CONSTRAINT fk_username FOREIGN KEY (username) REFERENCES users (username);

-- Test data --

insert into users
values ('lopus',
        '$pbkdf2$1drH02tXcgS5ipJIf8v/AlL/qm3CjAgAp7Qt3hyJx/c$/lONU4cTa3ayMRJbHIup47nX/1HhysyzDA0dpoFpsf727LoGH2OZ+SyFCGtv/pIEZK3mQtJv+yjzD+W0quF6xg');

insert into roles_perms
values ('dev', 'commit_code');
insert into roles_perms
values ('dev', 'eat_pizza');
insert into roles_perms
values ('admin', 'merge_pr');
insert into users_roles
values ('lopus', 'dev');
insert into users_roles
values ('lopus', 'admin');
