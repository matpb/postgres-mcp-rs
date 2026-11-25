\set ON_ERROR_STOP on
-- Created by the superuser after the recipe role exists: the default privilege must make it readable.
CREATE TABLE app.recipe_later (id int PRIMARY KEY, label text);
INSERT INTO app.recipe_later VALUES (1, 'created after the role');
