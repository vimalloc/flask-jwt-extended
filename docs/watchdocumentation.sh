watchmedo shell-command \
--patterns="*.rst" \
--ignore-pattern='_build/*' \
--recursive \
--command='make html'
