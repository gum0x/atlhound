#!/bin/python
import configparser
import logging
import re
import json
import time
from datetime import datetime
from jira import JIRA
from xml.sax.saxutils import escape
  
# Global variables
conn = None
issues_per_page=50
max_issues=1000
issue_ignore_file="issueignore.json"


def init_conn(configuration, conn_type):
    if conn_type == "jira":
        username = configuration["General"]["JIRA_USERNAME"]
        password = configuration["General"]["JIRA_PASSWORD"]
        URL = configuration["General"]["JIRA_URL"]
    elif conn_type == "confluence":
        username = configuration["General"]["CONFLUENCE_USERNAME"]
        password = configuration["General"]["CONFLLUENCE_PASSWORD"]
        URL = configuration["General"]["CONFLUENCE_URL"]
    else: 
        logging.error("Connection type not implemented yet... exiting")
        exit(1) 
    
    return JIRA(URL, auth=(username, password))  

def has_password_policy_compliant_words(text):
    complies=False
    #for match in re.findall("\S*[^a-zA-Z0-9\s]+\S*", text):
    for match in re.findall("\S{8,}", text):
        sum=0
        if len(match) >= 8:
            sum+=1
        if re.search("[a-z]",match):
            sum+=1
        if re.search("[A-Z]",match):
            sum+=1
        if re.search("[0-9]",match):
            sum+=1
        if re.search("[^a-zA-Z0-9\s]",match):
            sum+=1
        
        if re.search("https?:\/\/([a-zA-Z0-9\-]\.?)+\/.*",match):
            sum*=10
        if re.search("(Password:|Regards,|\[~[a-zA-Z0-9\.-]+\])",match):
            sum*=10
            
        if sum in [4,5]:
            logging.debug("Password Policy matched on: {}".format(match))
            complies=True
        
    return complies

def get_secrets(text):
    
    if re.search("[pP]asswords?\s*(:|to|is)\s*[a-zA-Z0-9]+", text):
        matches = re.search("[pP]asswords?\s*(:|to|is)\s*[a-zA-Z0-9]+", text)
        false_positive = False
        
        """
        if re.search("[Pp]assword.*reset.*sent", text):
            false_positive = True
        elif re.search("Password has been sent by email",text):
            false_positive = True 
        elif re.search("Password sent by email",text):
            false_positive = True
        elif re.search("^[Pp]assword reset (done )?in (prod|QA)$",text):
            false_positive = True
        """

        if not has_password_policy_compliant_words(text):
            false_positive = True

        if false_positive == False: 
            return matches

    if re.search("PASSWORD", text):
        if has_password_policy_compliant_words(text):
            return re.search("PASSWORD.*$", text)

    if re.search("[Pp]assword:?(\n|\xa0)?\s*[^\s]+",text):
        if has_password_policy_compliant_words(text):
            return re.search("[Pp]assword:?(\n|\xa0)+\s*[^\s]+.*$",text)
    
    return False
    

def jira_get_list_of_issues_by_keyword(configuration, already_checked_issues=None,updatedAfter=None):
    conn = init_conn(configuration, "jira")
    startat=0

    while True: 
        search = configuration["General"]["JIRA_DEFAULT_SEARCH"]
        if already_checked_issues:
            search += " AND issue NOT IN ({})".format(",".join(already_checked_issues))

        if updatedAfter:
            search += " AND updated >= '{}'".format(updatedAfter)

        search += " ORDER BY updated ASC"
        logging.debug("Final search query: {}".format(search))
        logging.debug("Pagination: issues_per_page({}), startAt({})".format(issues_per_page,startat))

        results = conn.search_issues(search, maxResults=issues_per_page, fields="summary, comment, description, updated",startAt=startat, expand='changelog')
        logging.debug("Search executed... {:d} results returned".format(len(results)))
        if len(results) > 0:
            for issue in results:
                logging.debug("Issue found in results:\n{}".format(issue.raw))
                yield issue
            startat+=issues_per_page
            if startat >= max_issues:
                logging.error("Reached the maxium of number of issues to process... exiting")
                break
        
        else:
            break
    

def jira_search_secrets_by_issue(issue, show_entire_object):
    # check Description for password
    logging.debug("Checking if issue {} has secrets on the description".format(issue.key))
    try:
        if issue.fields.description:
            secrets = get_secrets(issue.fields.description)
            if secrets:
                if show_entire_object:
                    print("Found password in issue {}'s description: {}".format(issue.key, escape(str(issue.fields.description))))
                else:
                    print("Found password in issue {}'s description: {}".format(issue.key, escape(secrets[0])))

    except Exception as err:
        logging.error("Error reading issue's description: {}".format(str(err)))
    
    logging.debug("Checking if issue {} has secrets on the comments".format(issue.key))
    try:
        for comment in issue.fields.comment.comments:
            secrets = get_secrets(comment.body)
            if secrets:
                if show_entire_object:
                    print("Found password in issue {}'s comment updated on {}: {}".format(issue.key, escape(comment.body),comment.updated))
                else:
                    print("Found password in issue {}'s comment updated on {}: {}".format(issue.key, escape(secrets[0]),comment.updated))
                        
    except Exception as err:
        logging.error("Error reading issue's comments: {}".format(str(err)))

    logging.debug("Checking if issue {} has secrets on the history".format(issue.key))
    try:
        for history in issue.changelog.histories:
            for item in history.items:
                fromString = str(item.fromString)
                secrets = get_secrets(fromString)
                if secrets:
                    if show_entire_object:
                        print("Found password in issue {}'s {} history created at {}: {}".format(issue.key, item.field,item.created, escape(fromString)))
                    else:
                        print("Found password in issue {}'s {} history created at {}: {}".format(issue.key, item.field,item.created, escape(secrets[0])))
            toString = str(history.items[-1].toString)
            secrets = get_secrets(toString)
            if secrets:
                if show_entire_object:
                    print("Found password in issue {}'s {} history created at {}: {}".format(issue.key, item.field,item.created, escape(fromString)))
                else:
                    print("Found password in issue {}'s {} history created at {}: {}".format(issue.key, item.field,item.created, escape(secrets[0])))

    except Exception as err:
        logging.error("Error reading issue's comments: {}".format(str(err)))


def get_issues_to_ignore():
    issues_to_ignore = {}
    try: 
        with open(issue_ignore_file) as infile:
            logging.debug("Loading {}...".format(issue_ignore_file))
            try: 
                issues_to_ignore = json.loads(infile.read())
            except Exception as err:
                logging.error("get_issues_to_ignore: {}".format(err))

    except Exception as err: 
        logging.error("Error reading the data from file...")

    return issues_to_ignore


def save_issues_to_ignore(issues_to_ignore):
    with open(issue_ignore_file, "w") as outfile:
        logging.debug("updating file with the new issues...")
        json.dump(issues_to_ignore, outfile)

        
if __name__ == "__main__":
    #logging.basicConfig(level=logging.DEBUG)
    execution_timestamp = time.time()
    logging.info("Script initiated...")

    try:
        config = configparser.ConfigParser()
        config.read('config.ini')
        logging.info('Configuration loaded')
    except Exception as err:
        logging.error("Exception: {}".format(str(err)))
        exit(1)

    search_window_file = config["General"]["SEARCHWINDOW_FILE"]
    try:
        with open(search_window_file, "r") as input_file:
            search_window = json.load(input_file)

    except Exception as err:
        logging.info("No {} file found or it wasn't possible to parse.\nErr:{}".format(search_window_file,str(err)))
        search_window = {}

    jira_date_fmt="%Y-%m-%dT%H:%M:%S.000%z"
    jql_date_fmt="%Y-%m-%d %H:%M"

    if not search_window:
        search_window = {"start": "1970-01-01T00:00:00.000+0100", "issues": []}
    
    search_window_start_datetime = datetime.strptime(search_window['start'],jira_date_fmt)    
    search_window_start = search_window_start_datetime.strftime(jql_date_fmt)
    
    already_ignored = get_issues_to_ignore()
    search_window_skip_issues = search_window["issues"]

    jira_tickets = jira_get_list_of_issues_by_keyword(config, list(already_ignored.keys()),search_window_start)
    processed_issues = {}
    logging.debug("Iterating returned issues...")

    for issue in jira_tickets:
        issue_updated_datetime = datetime.strptime(issue.fields.updated, jira_date_fmt)
        if issue.key not in already_ignored.keys() \
            and issue_updated_datetime >= search_window_start_datetime \
                and issue.key not in search_window_skip_issues:
            logging.debug("issue.raw: {}".format(issue.raw))
            try:
                jira_search_secrets_by_issue(issue,show_entire_object=True)
                processed_issues.update({issue.key: {"execution_time": execution_timestamp, "comment": ""}})
            except Exception as err: 
                logging.error("Can't retrieve or parse the issue {}. {}".format(issue.key,str(err)))
                logging.debug("Issue {}".format(json.dumps(str(issue.raw))))
            try:
                last_start_datetime_set = datetime.strptime(search_window['start'],jira_date_fmt)
                last_start_datetime_set_to_minute = datetime.strptime(last_start_datetime_set.strftime(jql_date_fmt),jql_date_fmt)
                current_issue_update_datetime = datetime.strptime(issue.fields.updated,jira_date_fmt)
                current_issue_update_datetime_to_minute = datetime.strptime(current_issue_update_datetime.strftime(jql_date_fmt),jql_date_fmt)

                logging.debug("last_start_datetime_set_to_minute: {}, current_issue_update_datetime_to_minute: {}".format(last_start_datetime_set_to_minute,current_issue_update_datetime_to_minute))
                if last_start_datetime_set_to_minute < current_issue_update_datetime_to_minute:
                    search_window["issues"] = [issue.key]
                if last_start_datetime_set_to_minute == current_issue_update_datetime_to_minute:
                    search_window["issues"].append(issue.key)

                search_window["start"] = issue.fields.updated

            except Exception as err:
                logging.info("Issue {} has no updated field. Setting created as start point".format(issue.key))
                #search_window["start"] = issue.raw

    if search_window_file:
        try:
            with open(search_window_file,"w") as outfile:
                json.dump(search_window,outfile)
                logging.info("Updated search window start value in {} file".format(search_window_file))
        except Exception as err:
            logging.error("Error ocurred while writing {} file: {}".format(search_window_file,str(err)))
    #already_ignored.update(processed_issues)
    #save_issues_to_ignore(already_ignored)
    #print("\n")
    #print("Processed issues:\n{}".format("\n".join(processed_issues.keys())))


