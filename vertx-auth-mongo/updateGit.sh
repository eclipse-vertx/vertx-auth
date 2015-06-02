#!/bin/sh

# SYNCHRONISIEREN DES LOKALEN REPO:
git fetch upstream  # ( holt Änderungen von Upstream Repo in Index ) 
git checkout master # ( switch auf master )

# git merge upstream/master # ( mergen in lokales Repo )

git status
