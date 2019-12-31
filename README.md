# althound 

althound is a python3 script that search within Jira/Confluence projects and issues for password and other keys. It should be useful for both red and blue teams. 

Tool is designed to be used as a manual tool that is launched manually by a supervisor as it returns comments with password and accounts from users. 

My major concert is security, so once I figure out how all process could be done automatically in a secure way I will try to develop this feature. 

Jira objects where search is conducted:
* comments
* description
* history

Conflunce support is not developed yet.

## TODO
* Jira: Is it needed to search on the description if we already search on the history?
* Jira: csv output with processed tools. 
* General: Automated flow for searching, notification and supervised processing
* General: Improve password searching function
* General: add argparser to make it configurable  