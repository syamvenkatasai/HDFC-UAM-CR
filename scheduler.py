"""
@author: Gopi Teja
Created Date: 2022-11-23
"""

import json
import schedule
import requests
import time
import os
from datetime import datetime, timedelta
import logging
import multiprocessing
import concurrent.futures
from db_utils import DB

from datetime import datetime, timedelta,date
from time import time as tt
from dateutil import parser

from pathlib import Path
from cryptography.fernet import Fernet

from ace_logger import Logging
logging = Logging()

# Database configuration
db_config = {
    'host': os.environ['HOST_IP'],
    'user': os.environ['LOCAL_DB_USER'],
    'password': os.environ['LOCAL_DB_PASSWORD'],
    'port': os.environ['LOCAL_DB_PORT']
}
# Write an function to hit the folder monitor flow
def start_folder_monitor(tenant_id, port, workflow_name):
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"Current Time:{current_time}")
    print(f"#### Started FM of {tenant_id}")
    host = os.environ.get('SERVER_IP')
    api_params = {}
    request_api = f'http://{host}:{port}/rest/engine/default/process-definition/key/{workflow_name}/start'
    headers = {'Content-type': 'application/json; charset=utf-8'}
    print(f"#### Hitting the camunda api of {request_api}")
    response = requests.post(request_api, json=api_params, headers=headers,verify=False)
    response_dict = json.loads(response.text)
    print(f"#### {tenant_id} FM Response Dict", response_dict)



def hit_get_files_from_sftp():
        print("Hitting get_files_from_sftp route...")
        host = 'foldermonitor'
        port = 443
        request_api = f'https://{host}:{port}/get_files_from_sftp'

        # Headers and payload
        headers = {'Content-type': 'application/json; charset=utf-8'}
        payload = {}  # Add any necessary data for the route if required

        try:
            response = requests.post(request_api, json=payload, headers=headers, verify=False)
            response_data = response.json()
            print(f"Response from get_files_from_sftp: {response_data}")
        except Exception as e:
            print(f"Error hitting get_files_from_sftp: {e}")

### For Multi Processing of a file 
def move_predo_do(tenant_id):
    try:
        print(f"move_predo_do: #### Started Moving from case creation to Seg of {tenant_id}")
        start = tt()
        db_config['tenant_id'] = tenant_id
        queue_db = DB('queues', **db_config)
        query = "select case_id, task_id, last_updated from queue_list where queue='case_creation' and case_creation_status IS NULL order by last_updated"
        predo_data = queue_db.execute_(query)

        if not predo_data.empty:
            # marking all the cases which picked here in this bucket as Picked to avoid duplicate picking
            cases = predo_data['case_id'].to_list()
            print(f"## Cases are {cases}")
            if len(cases) == 1:
                case=cases[0]
                query = f"UPDATE `queue_list` SET `case_creation_status` = CASE WHEN count_of_tries >= 3 THEN 'Failed' ELSE 'Picked' END WHERE `case_id` = '{case}'"
                #query=f"UPDATE `queue_list` SET `case_creation_status` ='Picked' WHERE `case_id` ='{case}' "
            elif len(cases) > 1:
                cases=tuple(cases)
                query = f""" UPDATE `queue_list` SET `case_creation_status` = CASE WHEN count_of_tries >= 3 THEN 'Failed' ELSE 'Picked' END ,count_of_tries = count_of_tries + 1 WHERE case_id IN {cases}"""
            queue_db.execute_(query)
            status_check_query = f"""
                                    SELECT case_id, case_creation_status
                                    FROM queue_list
                                    WHERE case_id IN {tuple(cases) if len(cases) > 1 else f"('{case}')"}
                                """
            updated_statuses = queue_db.execute_(status_check_query)
    
            # Filter cases where the status is not 'Failed'
            valid_cases = updated_statuses[
                updated_statuses['case_creation_status'] != 'Failed'
            ]

            if not valid_cases.empty:
                print(f"####: Valid cases for processing - {valid_cases['case_id'].to_list()}")
                valid_predo_data = predo_data[
                    predo_data['case_id'].isin(valid_cases['case_id'].to_list())
                ]
                move_predo_do_(tenant_id, valid_predo_data)
            else:
                print(f"####: No valid cases to process for tenant_id {tenant_id}")
        else:
            print(f"#### No cases for moving from {tenant_id}")
    except Exception as e:
        print("something went wrong while processing the cases", e)    


def move_predo_do_chunk(tenant_id, chunk):
    try:
        print(f"Started Moving Chunks {len(chunk)} records of tenant_id: {tenant_id}")
        start = tt()
        db_config['tenant_id'] = tenant_id
        queue_db = DB('queues', **db_config)
        headers = {'Content-type': 'application/json; charset=utf-8'}
        processed_cases = []
        failed_cases = []
        for index, row in chunk.iterrows():
            case_id = row['case_id']
            task_id = row['task_id']
            query = f"UPDATE `process_queue` set `accept_flag`= 1 where case_id='{case_id}'"
            queue_db.execute_(query)

            api_params = {"variables": {"button": {"value": 'Accept'}},'case_id': case_id, 'tenant_id': tenant_id}
            ## here camundaworkflow is the container name
            url = f'http://camundaworkflow:8080/rest/engine/default/task/{task_id}/complete'       
            print(f"move_predo_do_chunk: {datetime.now()} : hitting url for case_id: {case_id} to complete task: {url}")
            response = requests.post(url, json=api_params, headers=headers)
            response_json = response.json
            print(f"move_predo_do_chunk: response of {case_id} complete task: {response_json}")
            if response.status_code == 500:
                print(f'in if condition of 500 response')
                message = json.loads(response.content)
                message = message['message'].split(':')[0]
                #queue_db.execute_(f"update process_queue set accept_flag=0,error_logs='Failed in Predo-do: {message}' where case_id='{case_id}'")
                query_1=f"UPDATE `process_queue` set accept_flag=0, error_logs='{message}' where case_id='{case_id}'"
                # params_1 = [0,f'Failed in case_creation: {message}', case_id]
                # params_1 = [0,message, case_id]
                queue_db.execute(query_1)
                
                query_error = f" UPDATE `queue_list` SET `case_creation_status` = CASE WHEN count_of_tries = 3 THEN 'Failed' ELSE NULL END, count_of_tries = count_of_tries + 1, error_logs = '{message}' WHERE case_id = '{case_id}'"
                queue_db.execute_(query_error)
                query_2=f"UPDATE `queue_list` set case_creation_status=NULL where case_id='{case_id}'"
                count_query = f"SELECT count_of_tries FROM `queue_list` WHERE case_id = '{case_id}'"
                count_of_tries = queue_db.execute_(count_query)
                print(f'count_of_tries-----------{count_of_tries}')
                count_of_tries=count_of_tries['count_of_tries'].iloc[0]
                print(f'count_of_tries-----------{count_of_tries}')
                # if count_of_tries >= 3:
                #     return_data= {
                #         "case_id": case_id,
                #         "template": "case_processing_failure",
                #         "tenant_id": tenant_id
                #         }
                    
                #     host = 'emailtriggerapi'
                #     port = 80
                #     route = 'send_email_auto'
                #     print(f'Hitting URL: http://{host}:{port}/{route} for email_triggering')
                #     # logging.debug(f'Sending Data: {value_predict_params}')
                #     headers = {'Content-type': 'application/json; charset=utf-8',
                #             'Accept': 'text/json'}
                #     response = requests.post(
                #         f'http://{host}:{port}/{route}', json= return_data, headers=headers)
                    
                #     response=response.json()
                #     print(f" ####### Response Received from email_trigger is {response}")
                #     print(f"move_predo_do_chunk: File processing {case_id} is failed")


                # failed_cases.append(case_id)
                # print(f"move_predo_do_chunk: Camunda sent 500 the message is: {message}")
            elif response.status_code == 200:
                processed_cases.append(case_id)
                print(f"File processed {case_id} successfully")
                # queue_db.execute(f"update process_queue set accept_flag=1 where case_id='{case_id}'")
            elif response.status_code == 204:
                processed_cases.append(case_id)
                print(f"File processed {case_id} successfully")
            else:
                print(f"Some other status code is returning other than expected, status code: {response.status_code}")
                query_2=f"UPDATE `queue_list` set case_creation_status=NULL where case_id='{case_id}'"
                queue_db.execute_(query_2)
                query_reset = f"UPDATE `queue_list` SET `count_of_tries` = 0 WHERE `case_id` = '{case_id}'"
                queue_db.execute_(query_reset)
                failed_cases.append(case_id)
                print(f"move_predo_do_chunk: File processing {case_id} is failed")
        return processed_cases, failed_cases
    except Exception as e:
        print(f"Something went wrong while processing the chunk .. {e}.. {case_id}")

def move_predo_do_(tenant_id, predo_data):
    try:
        chunk_size = 1  # Define chunk size here
        chunks = [predo_data[i:i+chunk_size] for i in range(0, len(predo_data), chunk_size)]
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
            futures = []
            for chunk in chunks:
                print(f"## Chunk got is {chunk}")
                future = executor.submit(move_predo_do_chunk, tenant_id, chunk)
                futures.append(future)
                
            # Wait for any of the futures to complete and start new tasks if any are pending
            # while True:
            completed = concurrent.futures.wait(futures, return_when=concurrent.futures.FIRST_COMPLETED)
            for future in completed.done:
                futures.remove(future)
        print("All chunks processed successfully.")
            
    except Exception as e:
        print("something went wrong while processing the cases", e)



def uam_dormancy_scheduler(tenant_id):

    db_config['tenant_id'] = tenant_id
    db = DB('group_access', **db_config)
    try:
        dormant_rules_query = f"SELECT first_login_day, login_day,dormant_status from dormant_rules"
        dormant_rules = db.execute_(dormant_rules_query)

        first_login_day_limit = dormant_rules['first_login_day'].iloc[0]
        login_day_limit = dormant_rules['login_day'].iloc[0]
        dormant_status_users=json.loads(dormant_rules['dormant_status'].iloc[0])
        logging.info(f"first_login_day_limit :{first_login_day_limit},{login_day_limit},{dormant_status_users}")
        # Fetch data from active_directory
        act_dir_query = f"SELECT username, created_date, last_updated, status, previous_status FROM active_directory"
        act_dir = list(db.execute_(act_dir_query).to_dict(orient='records'))

        # Fetch data from live_sessions
        live_sess_query = f"SELECT last_request_new, user_ FROM live_sessions"
        live_sess = list(db.execute_(live_sess_query).to_dict(orient='records'))

        userss = [entry['USER_'] for entry in live_sess]

        logging.info("Data fetched from database.")
        live_sess_query = f"SELECT status, user_ FROM live_sessions"
        live_sess_active = list(db.execute_(live_sess_query).to_dict(orient='records'))
    except Exception as e:
        logging.info("Error fetching data from the database:", e)

    try:
        # Format live session last_request dates
        for entry in live_sess:
            if entry['last_request_new']:
                entry['last_request_new'] = entry['last_request_new'].strftime('%Y-%m-%d %H:%M:%S')
        logging.info("Live sessions formatted:", live_sess)

        # Prepare a dictionary for fast lookup
        live_sess_dict = {entry['user_']: entry['last_request_new'] for entry in live_sess}
        
        live_sess_active_dict = {entry['user_']: entry['status'] for entry in live_sess_active}

        # Get system date
        sys_date = (datetime.now()+timedelta(hours=5 , minutes=30)).date()

        # Initialize results
        dormant_users = []
        def parse_date(date_str):
            """Parses a string into a date object (without time)."""
            if isinstance(date_str, datetime):
                return date_str.date()  # Convert to date only
            try:
                return parser.parse(date_str).date() if date_str else None  # Extract date only
            except Exception as e:
                logging.info(f"Error parsing date {date_str}: {e}")
                return None

        # Process each user in the active directory
        for user in act_dir:
            username = user.get('USERNAME')
            created_date = parse_date(user.get('CREATED_DATE'))
            updated_date = parse_date(user.get('LAST_UPDATED'))
            status = user.get('STATUS')
            previous_status = user.get('PREVIOUS_STATUS')
            # if live_sess_active_dict.get(username)=='active':
            #     continue
            if status=='delete' or status=='disable':
                continue
            # Parse previous_status JSON

            try:
                parsed_previous_status = json.loads(previous_status) if previous_status else []
            except Exception as e:
                logging.info(f"Error parsing previous_status for {username}: {e}")
                parsed_previous_status = []
            try:
                # Get last login date from live sessions
                last_login_date = parse_date(live_sess_dict.get(username))

                # Determine the most recent activity date
                # valid_dates = [date for date in [created_date, updated_date, last_login_date] if date]
                # recent_activity_date = max(valid_dates) if valid_dates else None

                # Calculate inactivity period
                # if recent_activity_date:
                #     inactive_days = (sys_date - recent_activity_date).days
                # else:
                #     inactive_days = (sys_date - created_date).days if created_date else float('inf')

                # logging.info(f"User: {username}, Inactive Days: {inactive_days}")

                # Check dormancy conditions

                # Condition 1: User is created and first_login_day_limit days have passed since creation
                if created_date and (sys_date - created_date).days >= first_login_day_limit and username not in userss:
                    dormant_users.append(username)
                    logging.info(f"User '{username}' is now dormant as he was not login within dormancy period from created date.")

                # Condition 2: Last login was more than login_day_limit days 
                elif last_login_date and (sys_date - last_login_date).days >= login_day_limit:
                    dormant_users.append(username)
                    logging.info(f"User '{username}' is now in dormant as he was not login within dormancy period from last login date.")

                # Condition 3: User is created and locked on the same day, has not logged in
                elif status == "lock" and created_date == updated_date and ((sys_date - updated_date).days >= login_day_limit or (sys_date - updated_date).days >= first_login_day_limit):
                    dormant_users.append(username)
                    logging.info(f"User '{username}' created and locked on the same day is now dormant.")

                # Condition 4: Reactivated dormant user without login on the activation day
                elif parsed_previous_status[-1] == 'dormant' and (sys_date - updated_date).days <= 1:
                    dormant_users.append(username)
                    logging.info(f"User '{username}' is now in dormant as he was not login on the day of reactivation")
                if username in dormant_status_users and status == "lock" and (sys_date - last_login_date).days <= 1:
                    dormant_users.append(username)
                if status=='dormant' and username not in dormant_users:
                    dormant_users.append(username)
            except Exception as e:
                logging.info(f"Error : {e}")
        dormant_users_update=f"update dormant_rules set dormant_status='{json.dumps(dormant_users)}' where id=1"
        db.execute_(dormant_users_update)
        if dormant_users:
            username_str = "', '".join(dormant_users)
            query = f"""
                UPDATE active_directory
                SET status = 'dormant'
                WHERE username IN ('{username_str}')
            """
            db.execute_(query)
            logging.info(f"Users marked as dormant: {dormant_users}")
        else:
            logging.info("No users to update.")
    except Exception as e:
        logging.info("Error processing dormancy logic:", e)



def hit_get_files_from_sftp_masters():
    print("Hitting get_files_from_sftp_masters...")
    host = 'masterupload'
    port = 443
    request_api = f'https://{host}:{port}/get_files_from_sftp_masters'

    # Headers and payload
    headers = {'Content-type': 'application/json; charset=utf-8'}
    payload = {}  # Add any necessary data for the route if required

    try:
        response = requests.post(request_api, json=payload, headers=headers, verify=False)
        response_data = response.json()
        print(f"Response from get_files_from_sftp_masters: {response_data}")
    except Exception as e:
        print(f"Error hitting get_files_from_sftp_masters: {e}")



def run_schedule(job_func,interval=None, at_time=None, *args):
    if at_time:
        # Schedule to run daily at a specific time
        print("at_timeeee--------------")
        schedule.every().day.at(at_time).do(job_func, *args)
    elif interval:
        # Schedule to run periodically at a fixed interval in seconds
        print("intervel-------")
        schedule.every(interval).seconds.do(job_func, *args)
    else:
        raise ValueError("You must specify either an interval or at_time.")
    while True:
        schedule.run_pending()
        time.sleep(1)

# Call that function
schedule.every(10).seconds.do(start_folder_monitor,'hdfc','8080', 'hdfc_folder_monitor')
schedule.every(10).seconds.do(hit_get_files_from_sftp)
# schedule.every(1).hour.do(start_folder_monitor, 'hdfc', '8080', 'hdfc_folder_monitor')

# schedule.every(45).minutes.do(hit_get_files_from_sftp)

schedule.every().day.at("03:30").do(hit_get_files_from_sftp_masters)

# This below line code is useful for hitting the camunda work flow for master data upload 5h:30 min below because of server time
schedule.every().day.at("03:32").do(start_folder_monitor, 'hdfc', '8080', 'folder_monitor_sftp')
schedule.every().day.at("03:33").do(start_folder_monitor, 'hdfc', '8080', 'folder_monitor_sftp')
schedule.every().day.at("03:34").do(start_folder_monitor, 'hdfc', '8080', 'folder_monitor_sftp')


if __name__ == '__main__':
    while True:

        mode = os.environ.get('MODE')
        auto_dormancy_process = multiprocessing.Process(target=run_schedule, args=(uam_dormancy_scheduler,None,"18:33", 'hdfc'))
        move_predo_process = multiprocessing.Process(target=run_schedule, args=(move_predo_do, 20,None, 'hdfc'))
        move_predo_process.start()
        auto_dormancy_process.start()

        move_predo_process.join()
        auto_dormancy_process.join()
        print("##########Mode is ",mode)
        if mode == "UAT":
            print("####In UAT ---> Hitting servers in the UAT only###")
        else:
            print("######In DEV mode")

        schedule.run_pending()
        time.sleep(1)
