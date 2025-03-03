import json
import requests
import traceback
import os
import sqlalchemy
import pandas as pd
import psutil
import jwt
import re
from dateutil import parser
from db_utils import DB
from flask import Flask, request, jsonify
from time import time as tt
from sqlalchemy.orm import sessionmaker
from hashlib import sha256
from elasticsearch_utils import elasticsearch_search
from py_zipkin.util import generate_random_64bit_string
from py_zipkin.zipkin import zipkin_span, ZipkinAttrs, create_http_headers_for_new_span
from ace_logger import Logging
from app import app
from datetime import datetime,timedelta

import pytz
tmzone = 'Asia/Kolkata'
import random
import string


logging = Logging()

db_config = {
    'host': os.environ['HOST_IP'],
    'port': os.environ['LOCAL_DB_PORT'],
    'user': os.environ['LOCAL_DB_USER'],
    'password': os.environ['LOCAL_DB_PASSWORD']
}

def http_transport(encoded_span):
    body = encoded_span
    requests.post(
        'http://servicebridge:80/zipkin',
        data=body,
        headers={'Content-Type': 'application/x-thrift'},
    )
def measure_memory_usage():
    process = psutil.Process()
    memory_info = process.memory_info()
    return memory_info.rss  # Resident Set Size (RSS) in bytes

def insert_into_audit(data):
    tenant_id = data.pop('tenant_id')
    db_config['tenant_id'] = tenant_id
    stats_db = DB('stats', **db_config)
    stats_db.insert_dict(data, 'audit_')
    return True

@app.route('/role_approval', methods=['POST', 'GET'])
def role_approval():
    data = request.json
    logging.info(f"data : {data}")
    user = data.get('user', None)
    session_id=data.get('session_id',None)
    flag = data.get('flag', None)
    try:
        memory_before = measure_memory_usage()
        start_time = tt()
    except Exception:
        logging.warning("Failed to start ram and time calc")
    
    trace_id = generate_random_64bit_string()
    tenant_id = os.environ.get('TENANT_ID',None)

    attr = ZipkinAttrs(
        trace_id=trace_id,
        span_id=generate_random_64bit_string(),
        parent_span_id=None,
        flags=None,
        is_sampled=False,
        tenant_id=tenant_id
    )

    with zipkin_span(
        service_name='user_management',
        span_name='role_approval',
        transport_handler=http_transport,
        zipkin_attrs=attr,
        port=5010,
        sample_rate=0.5
        ):
        try:
            db_config['tenant_id'] = tenant_id
            db = DB('group_access', **db_config)
        except Exception as e:
            logging.error(f"Database connection failed: {e}")
            return {"flag": False, "data": {"message": "Database connection failed."}}

        try:
            current_ist = datetime.now(pytz.timezone(tmzone))
            currentTS = current_ist.strftime('%Y-%m-%d %H:%M:%S')
            if flag == "create":
                new_role_name=data.get('new_role_name', None)
                role_description=data.get('role_description', None)
                type_of_access=data.get('type_of_access',None)
                profile_assigned_to=data.get('profile_assigned_to',None)
                rights_info=data.get('rights_info',{})
                if ((rights_info['Add User'] or rights_info['Modify User'] or rights_info['Add Roles'] or rights_info['Modify Roles']) and (rights_info['Approve UAM Maker Activity']  or rights_info['Reject UAM Maker Activity'])) or (rights_info['View All Queues'] and rights_info['Modify All Queues']):
                    return {"flag": False, "message": "Coflict occurs"}
                
                try:
                    query="SELECT group_name FROM group_definition"
                    existing_roles=db.execute_(query)['group_name'].tolist()

                except Exception as e:
                    logging.error(f"Query failed,Error:{e}")
                    return {"flag":False,"message":"Error fetching existing roles."}
                if new_role_name in existing_roles:
                    return {"flag": False, "message": "Role already exists."}
                try:
                    query=f"SELECT distinct role_name FROM role_rights_modifications where status='waiting'"
                    verification_roles=db.execute_(query)['role_name'].tolist()

                except Exception as e:
                    logging.error(f"Query failed,Error:{e}")
                    return {"flag":False,"message":"Error fetching roles."}
                if new_role_name in verification_roles:
                    return {"flag": False, "message": "Created Role already sent for verification"}
                dictvals = {
                    "Add User":"add_user",
                    "Modify User":"modify_user",
                    "Add Business Rule":"add_business_rule",
                    "Modify Business Rule":"modify_business_rule",
                    "Add Roles":"add_roles",
                    "Modify Roles":"modify_roles",
                    "View All Queues":"view_all_queues",
                    "Modify All Queues":"modify_all_queues",
                    "Master Data Edit":"master_data_edit",
                    "Bulk Transaction":"bulk_transaction",
                    "Approve UAM Maker Activity":"approve_uam_maker_activity",
                    "Reject UAM Maker Activity":"reject_uam_maker_activity",
                    "Approve edits to Master": "approve_edits_to_master",
                    "Reject edit to Master":"reject_edit_to_master",
                    "Approve change in Business Rule":"approve_change_in_business_rule",
                    "Reject change in Business Rule":"reject_change_in_business_rule",
                    "Operation Reports":"operation_reports",
                    "UAM Reports":"uam_reports"
                }
                true_rights = [key for key, value in rights_info.items() if value]
                true_rights_list = str(true_rights).replace("'", '"')
                role_rights_history_query=f"""
                        INSERT INTO role_rights_history
                            (role_name, role_rights, status, updated_by, approved_by, updated_date) 
                        VALUES 
                            ('{new_role_name}','{true_rights_list}', 'Waiting for Approval', '{user}', '', TO_TIMESTAMP('{currentTS}', 'YYYY-MM-DD HH24:MI:SS'))
                        """
                db.execute_(role_rights_history_query)
                for right, status in rights_info.items():
                    try:
                        data_to_insert = {
                            'ROLE_NAME': new_role_name,
                            'DISPLAY_ROLE_RIGHTS': right,
                            'ROLE_RIGHTS': dictvals.get(right, right),
                            'STATUS': 'waiting',
                            'RIGHTS_ASSIGNED_STATUS': 'Yes' if status else 'No',
                            'UAMMAKER': user,
                            'UAMMAKER_DATE': currentTS,
                            'ROLE_DESCRIPTION':role_description,
                            'TYPE_OF_ACCESS':type_of_access,
                            'PROFILE_ASSIGNED_TO':profile_assigned_to
                        }

                        filtered_data = {k: v for k, v in data_to_insert.items() if v != ''}
                        
                        columns_list = ', '.join(filtered_data.keys())

                        values_list = ', '.join(
                            f"TO_TIMESTAMP('{str(v)}', 'YYYY-MM-DD HH24:MI:SS')" if k == "UAMMAKER_DATE" 
                            else f"'{str(v).replace("'", "''")}'" 
                            for k, v in filtered_data.items()
                        )

                        query = f"INSERT INTO role_rights_modifications ({columns_list}) VALUES ({values_list})"

                        db.execute_(query)
                    
                    except Exception as e:
                        logging.error(f"Query failed ,Error:{e}")
                        return {"flag":False,"message":"Error inserting role rights modifications."}

                response_data= {"flag": True, "message": "Role created successfully! Sent for Approval"}
            
            if flag == "accept":
                role_name = data.get('selected_role', None)
                approval_comments=data.get('approval_comment',None)

                query = f"SELECT role_name FROM role_rights_modifications WHERE role_name ='{role_name}' and status='waiting'"
                waiting_roles = db.execute_(query)['role_name'].tolist()
                logging.info(f"waiting_roles:{waiting_roles}")
                if not waiting_roles:
                    return jsonify({"flag": False, "message": "No modifications found for approval"})
                try:
                    query = "SELECT id FROM group_definition"
                    id_df =db.execute_(query)['id'].tolist()
                    id_dff=max(id_df)+1
                    data_to_insert = {
                        'ID': id_dff,
                        'GROUP_NAME': role_name,
                        'GROUP_DEFINITION': json.dumps({"role": [role_name]}),
                        'GROUP_DEFINITION_TEMPLATE': json.dumps({"roles": ["role"]}),
                        'STATUS': 'enabled',
                        'CREATED_DATE': currentTS,
                        'PREV_STATUS':'enabled',
                    }

                    filtered_data = {k: v for k, v in data_to_insert.items() if v != ''}

                    columns_list = ', '.join(filtered_data.keys())
                    values_list = ', '.join(
                        f"TO_TIMESTAMP('{str(v)}', 'YYYY-MM-DD HH24:MI:SS')" if k == "CREATED_DATE"
                        else f"'{str(v).replace("'", "''")}'"
                        for k, v in filtered_data.items()
                    )
                    insert_query = f"INSERT INTO group_definition ({columns_list}) VALUES ({values_list})"
                    db.execute(insert_query)
                    logging.info(f'#####insert_query is {insert_query}')
                    query_result = db.execute_(insert_query)
                    logging.info(f'#####query_result is {query_result}')
                    insert_query = f"INSERT INTO attribute_dropdown_definition (ATTRIBUTE_ID,PARENT_ATTRIBUTE_VALUE,VALUE) VALUES ({id_dff},'','{role_name}')"
                    db.execute(insert_query)
                    insert_query = f"INSERT INTO organisation_attributes (SOURCE,ATTRIBUTE,ATT_ID) VALUES ('user','role','{id_dff}')"
                    db.execute(insert_query)
                    insert_query = f"INSERT INTO organisation_hierarchy(ID,H_GROUP,SOURCE,H_ORDER,PARENT) VALUES ('{id_dff}','roles','user','role','')"
                    db.execute(insert_query)
                    query = f"UPDATE role_rights_modifications SET status = 'completed',approval_comment='{approval_comments}' WHERE role_name = '{role_name}'"
                    db.execute(query)

                    query = f"""
                    INSERT INTO role_rights (
                        ROLE_NAME,
                        DISPLAY_ROLE_RIGHTS,
                        ROLE_RIGHTS,
                        STATUS,
                        NEW_RIGHTS_ASSIGNED_STATUS,
                        UAMMAKER,
                        UAMMAKER_DATE,
                        UAMCHECKER,
                        UAMCHECKER_DATE,
                        OLD_RIGHTS_ASSIGNED_STATUS,
                        ROLE_DESCRIPTION,
                        TYPE_OF_ACCESS,
                        PROFILE_ASSIGNED_TO
                    )
                    SELECT 
                        ROLE_NAME,
                        DISPLAY_ROLE_RIGHTS,
                        ROLE_RIGHTS,
                        'enabled',
                        RIGHTS_ASSIGNED_STATUS AS OLD_RIGHTS_ASSIGNED_STATUS,
                        UAMMAKER,
                        UAMMAKER_DATE,
                        '{user}' AS UAMCHECKER, 
                        TO_TIMESTAMP('{currentTS}', 'YYYY-MM-DD HH24:MI:SS') AS UAMCHECKER_DATE,   
                        NULL,
                        ROLE_DESCRIPTION,
                        TYPE_OF_ACCESS,
                        PROFILE_ASSIGNED_TO
                    FROM role_rights_modifications WHERE role_name = '{role_name}'
                    """
                    logging.info(f'#####insert_query is {insert_query}')
                    query_result = db.execute_(query)
                    logging.info(f'#####query_result is {query_result}')
                    history_appr_query = f"""
                                UPDATE role_rights_history
                                SET status = 'Accepted',
                                    approved_by = '{user}',
                                    updated_date = TO_TIMESTAMP('{currentTS}', 'YYYY-MM-DD HH24:MI:SS')
                                WHERE role_name = '{role_name}' and LOWER(status) = 'waiting for approval'
                            """

                    db.execute_(history_appr_query)
                except Exception as e:
                    logging.error(f"Query failed , Error:{e}")

                response_data={"flag": True, "message": "Role approved successfully"}

            if flag == "rejected":
                try:
                    role_name = data.get('selected_role', None)
                    rejected_comments=data.get('rejected_comment',None)

                    query = f"""
                        UPDATE role_rights_modifications 
                        SET rejected_comments = '{rejected_comments}', status = 'rejected' 
                        WHERE role_name = '{role_name}' and status='waiting'
                    """
                    db.execute_(query)

                    history_rej_query = f"""
                                UPDATE role_rights_history
                                SET status = 'Rejected',
                                    approved_by = '{user}',
                                    updated_date = TO_TIMESTAMP('{currentTS}', 'YYYY-MM-DD HH24:MI:SS')
                                WHERE role_name = '{role_name}' and LOWER(status) = 'waiting for approval'
                            """
                    db.execute_(history_rej_query)
                except Exception as e:
                    logging.error(f"Query failed,Error:{e}")
                    return {"flag":False,"message":"Error rejecting role."}

                response_data = {"flag": True,"message": "Role rejected successfully."}
            
        except Exception as e:
            logging.info("Something went wrong in updating data:", {e})
            response_data={"flag": False,"message":"Something went wrong"}

        try:
            memory_after = measure_memory_usage()
            memory_consumed = (memory_after - memory_before) / \
                (1024 * 1024 * 1024)
            end_time = tt()
            time_consumed = str(end_time-start_time)
            memory_consumed = f"{memory_consumed:.10f}"
            time_consumed = str(round(end_time-start_time, 3))
        except Exception as e:
            logging.warning("Failed to calc end of ram and time")
            logging.exception("ram calc went wrong")
            memory_consumed = None
            time_consumed = None
        audit_data = {"tenant_id": tenant_id, "user_": user,
                        "api_service": "modify_user", "service_container": "user_management", "changed_data": None,
                        "tables_involved": "","memory_usage_gb": str(memory_consumed), 
                        "time_consumed_secs": time_consumed, "request_payload": json.dumps(data), 
                        "response_data": str(response_data['message']), "trace_id": trace_id, "session_id": session_id,"status":str(response_data['flag'])}
        insert_into_audit(audit_data)
        return jsonify(response_data)

@app.route('/update_role_rights', methods=['POST', 'GET'])
def update_role_rights():
    data = request.json
    logging.info(f"data : {data}")
    user = data.get('user', None)
    session_id=data.get('session_id,None')
    flag=data.get('flag',None)
    try:
        memory_before = measure_memory_usage()
        start_time = tt()
    except Exception:
        logging.warning("Failed to start ram and time calc")
        
    
    trace_id = generate_random_64bit_string()
    tenant_id = os.environ.get('TENANT_ID',None)

    attr = ZipkinAttrs(
        trace_id=trace_id,
        span_id=generate_random_64bit_string(),
        parent_span_id=None,
        flags=None,
        is_sampled=False,
        tenant_id=tenant_id
    )

    with zipkin_span(
        service_name='user_management',
        span_name='update_role_rights',
        transport_handler=http_transport,
        zipkin_attrs=attr,
        port=5010,
        sample_rate=0.5
        ):
        try:
            db_config['tenant_id'] = tenant_id
            db = DB('group_access', **db_config)
        except Exception as e:
            logging.error(f"Database connection failed: {e}")
            return {"flag": False, "data": {"message": "Database connection failed."}}

        try:
            current_ist = datetime.now(pytz.timezone(tmzone))
            currentTS = current_ist.strftime('%Y-%m-%d %H:%M:%S')
            if flag=='update':
                updated_rights=data.get('updated_rights', {})
                role_name_changes=data.get('role_name_changes',{})
                role_name_map = {str(item): value.strip()for item,value in role_name_changes.items()}
                logging.info(f"role_name_map:{role_name_map}")
                all_updated_roles=[]
                for exist_role,rights_info_df in updated_rights.items():
                    rights_info=rights_info_df.get('rights_assigned',{})
                    all_updated_roles.append(exist_role)
                    if (rights_info['Add User'] or rights_info['Modify User'] or rights_info['Add Roles'] or rights_info['Modify Roles']) and (rights_info['Approve UAM Maker Activity']  or rights_info['Reject UAM Maker Activity']) or (rights_info['View All Queues'] and rights_info['Modify All Queues']):
                        return {"flag": False, "message": "Coflict occurs"}
                
                # try:
                #     if all_updated_roles:  # Ensure the list is not empty
                #         roles_str = ", ".join(f"'{role}'" for role in all_updated_roles)  # Format roles correctly
                #         query = f"SELECT DISTINCT status FROM active_directory WHERE role IN ({roles_str})"
                        
                #         result = db.execute_(query)  # Execute query
                        
                #         if isinstance(result, pd.DataFrame):  # If result is a DataFrame
                #             user_role_status = result.to_dict(orient='records')
                #         elif isinstance(result, pd.Series):  # If result is a Series
                #             user_role_status = result.tolist()
                #         else:
                #             user_role_status = result  # Handle other cases

                #         logging.info(f"user_role_status: {user_role_status}")
                #     else:
                #         logging.warning("all_updated_roles is empty. Skipping query execution.")
                #         user_role_status = []  # Return an empty list if no roles exist

                # except Exception as e:
                #     logging.error(f"Error fetching waiting roles: {e}")


                # try:
                #     roles_str = ", ".join(f"'{role}'" for role in all_updated_roles)  # Format properly
                #     query = f"SELECT DISTINCT status FROM active_directory WHERE role IN ({roles_str})"
                #     user_role_status = db.execute_(query)['status'].to_dict(orient='records')
                #     logging.info(f"user_role_status:{user_role_status}")
                # except Exception as e:
                #     logging.error(f"Error fetching waiting roles: {e}")
                
                
                try:
                    query = "SELECT distinct role_name FROM role_rights_modifications WHERE status='waiting'"
                    waiting_roles = db.execute_(query)['role_name'].tolist()
                    logging.info(f"waiting_roles:{waiting_roles}")
                except Exception as e:
                    logging.error(f"Error fetching waiting roles: {e}")
                for exist_role,rights_info_df in updated_rights.items():

                    query = f"SELECT DISTINCT status FROM active_directory WHERE role='{exist_role}' and status='enable'"
                    result = db.execute_(query)["status"].tolist()
                    logging.info(f"user_role_status: {result}")
                    if result!=[]:
                        return jsonify({"flag": False, "message": f"Users are in Active state for this Role"})
                    logging.info(f"exist_role:{exist_role}")
                    if exist_role in waiting_roles:
                        return jsonify({"flag": False, "message": "Already waiting for approval"})
                    try:
                        is_role_enabled='enabled' if rights_info_df.get('isRoleEnabled')==True else 'disabled'
                        rights_info=rights_info_df.get('rights_assigned',{})

                        dictvals = {
                        "Add User":"add_user",
                        "Modify User":"modify_user",
                        "Add Business Rule":"add_business_rule",
                        "Modify Business Rule":"modify_business_rule",
                        "Add Roles":"add_roles",
                        "Modify Roles":"modify_roles",
                        "View All Queues":"view_all_queues",
                        "Modify All Queues":"modify_all_queues",
                        "Master Data Edit":"master_data_edit",
                        "Bulk Transaction":"bulk_transaction",
                        "Approve UAM Maker Activity":"approve_uam_maker_activity",
                        "Reject UAM Maker Activity":"reject_uam_maker_activity",
                        "Approve edits to Master": "approve_edits_to_master",
                        "Reject edit to Master":"reject_edit_to_master",
                        "Approve change in Business Rule":"approve_change_in_business_rule",
                        "Reject change in Business Rule":"reject_change_in_business_rule",
                        "Operation Reports":"operation_reports",
                        "UAM Reports":"uam_reports"
                        }
                        for right, status in rights_info.items():
                            data_to_insert = {
                                'ROLE_NAME': exist_role,
                                'DISPLAY_ROLE_RIGHTS': right,
                                'ROLE_RIGHTS': dictvals.get(right, right),
                                'STATUS': 'waiting',
                                'RIGHTS_ASSIGNED_STATUS': 'Yes' if status else 'No',
                                'UAMMAKER': user,
                                'UAMMAKER_DATE': currentTS,
                                'new_role_name': role_name_map.get(exist_role,exist_role)
                            }
                            logging.info(f"data_to_insert :{data_to_insert}")

                            filtered_data = {k: v for k, v in data_to_insert.items() if v != ''}
                            
                            columns_list = ', '.join(filtered_data.keys())

                            values_list = ', '.join(
                                f"TO_TIMESTAMP('{str(v)}', 'YYYY-MM-DD HH24:MI:SS')" if k == "UAMMAKER_DATE" 
                                else f"'{str(v).replace("'", "''")}'" 
                                for k, v in filtered_data.items()
                            )

                            query = f"INSERT INTO role_rights_modifications ({columns_list}) VALUES ({values_list})"

                            db.execute_(query)
                        true_rights = [key for key, value in rights_info.items() if value]
                        true_rights_list = str(true_rights).replace("'", '"')
                        role_rights_history_query=f"""
                                INSERT INTO role_rights_history
                                    (role_name, role_rights, status, updated_by, approved_by, updated_date) 
                                VALUES 
                                    ('{exist_role}','{true_rights_list}', 'Waiting for Approval', '{user}', '', TO_TIMESTAMP('{currentTS}', 'YYYY-MM-DD HH24:MI:SS'))
                                """
                        db.execute_(role_rights_history_query)
                        try:
                            query=f"SELECT status FROM group_definition where group_name='{exist_role}'"
                            role_status=db.execute_(query)['status'].iloc[0]
                            logging.info(f"role_status:{role_status},is_role_enabled:{is_role_enabled}")
                        except Exception as e:
                            logging.error(f"Query failed,Error:{e}")
                            return {"flag":False,"message":"Error fetching existing role status."} 
                        query = f"UPDATE group_definition SET prev_status ='{is_role_enabled}' WHERE group_name = '{exist_role}'"
                        db.execute_(query)
                        if role_status!= is_role_enabled:
                            if is_role_enabled=='disabled':
                                return {"flag":True,"message":"Role deactivated Successfully and Record sent for Approval"}
                            elif is_role_enabled=='enabled':
                                return {"flag":True,"message":"Role activated Successfully and Record sent for Approval"}
                        
                    except Exception as e:
                        logging.error(f"Error updating role rights for {exist_role}: {e}")
                        return {"flag": False, "message": " Error in Role updation"}
                response_data= {"flag": True, "message": "Role updated successfully and Record sent for Approval"}
            if flag=='approve':
                try:
                    role=data.get("selected_role")

                    query = f"""SELECT DISTINCT uammaker,new_role_name, uammaker_date FROM role_rights_modifications WHERE role_name = '{role}' AND status = 'waiting'"""
                    role_dates=db.execute_(query)
                    
                    updated_by=role_dates['uammaker'].iloc[0]
                    updated_date=role_dates['uammaker_date'].iloc[0]
                    new_role_name=role_dates['new_role_name'].iloc[0]
                    logging.info(f'new_role_name:{new_role_name}')
                    query = f"UPDATE role_rights SET old_rights_assigned_status = new_rights_assigned_status,uammaker='{updated_by}',uammaker_date=TO_TIMESTAMP('{updated_date}', 'YYYY-MM-DD HH24:MI:SS'),uamchecker='{user}',uamchecker_date=TO_TIMESTAMP('{currentTS}', 'YYYY-MM-DD HH24:MI:SS') WHERE role_name = '{role}'"
                    db.execute_(query)
                    
                    query=f"""
                        UPDATE role_rights rr
                        SET NEW_RIGHTS_ASSIGNED_STATUS = (
                            SELECT rrm.RIGHTS_ASSIGNED_STATUS
                            FROM role_rights_modifications rrm
                            WHERE rr.ROLE_NAME = rrm.ROLE_NAME
                            AND rr.ROLE_RIGHTS = rrm.ROLE_RIGHTS
                            AND rrm.status = 'waiting'
                            FETCH FIRST 1 ROW ONLY
                        )
                        WHERE rr.ROLE_NAME = '{role}'
                        AND EXISTS (
                            SELECT 1 FROM role_rights_modifications rrm
                            WHERE rr.ROLE_NAME = rrm.ROLE_NAME
                            AND rr.ROLE_RIGHTS = rrm.ROLE_RIGHTS
                            AND rrm.status = 'waiting'
                        )
                    """
                    db.execute_(query)
                    history_appr_query = f"""
                                UPDATE role_rights_history
                                SET status = 'Accepted',
                                    approved_by = '{user}',
                                    updated_date = TO_TIMESTAMP('{currentTS}', 'YYYY-MM-DD HH24:MI:SS')
                                WHERE role_name = '{role}' and LOWER(status) = 'waiting for approval'
                            """

                    db.execute_(history_appr_query)
                    if new_role_name != role:
                        query = f"UPDATE role_rights SET role_name = '{new_role_name}' WHERE role_name = '{role}'"
                        db.execute_(query)
                        
                        query = f"UPDATE active_directory SET role = '{new_role_name}' WHERE role = '{role}'"
                        db.execute_(query)
                        
                        query = f"UPDATE active_directory_modifications SET role = '{new_role_name}' WHERE role = '{role}' AND STATUS NOT IN ('approved', 'rejected')"
                        db.execute_(query)
                        
                        query = f"UPDATE group_definition SET group_name = '{new_role_name}', group_definition = '{json.dumps({'role': [new_role_name]})}' WHERE group_name = '{role}'"
                        db.execute_(query)
                        
                        query = f"UPDATE attribute_dropdown_definition SET value = '{new_role_name}' WHERE value = '{role}'"
                        db.execute_(query)

                        query = f"UPDATE group_definition SET status = prev_status,disabled_date=TO_TIMESTAMP('{currentTS}', 'YYYY-MM-DD HH24:MI:SS') WHERE group_name = '{new_role_name}'"
                        db.execute_(query)
                    else:
                        query = f"UPDATE group_definition SET status = prev_status,disabled_date=TO_TIMESTAMP('{currentTS}', 'YYYY-MM-DD HH24:MI:SS') WHERE group_name = '{role}'"
                        db.execute_(query)
                    query = f"UPDATE role_rights_modifications SET status = 'completed' WHERE role_name = '{role}' and status='waiting'"
                    db.execute_(query)
                    response_data= {"flag": True, "message": "Role Approved successfully."}
                except Exception as e:
                    logging.error(f"Error approving role {role}: {e}")
                    response_data= {"flag": False, "message": "Error in role approval"}

            if flag=='reject':
                try:
                    role_name = data.get('selected_role', None)
                    rejected_comments=data.get('rejected_comments',None)
                    logging.info(f"role_name:{role_name}")
                    query1 = f"SELECT role_rights,rights_assigned_status FROM role_rights_modifications WHERE role_name='{role_name}' and status='waiting'"
                    query2 = f"SELECT role_rights,new_rights_assigned_status FROM role_rights WHERE role_name='{role_name}'"
                    df_modifications=db.execute_(query1)
                    df_rights= db.execute_(query2)
                    df_merged = pd.merge(df_modifications, df_rights, on="role_rights", how="inner")
                    df_mismatch = df_merged[df_merged["rights_assigned_status"] != df_merged["new_rights_assigned_status"]]

                    mismatched_role_rights = df_mismatch["role_rights"].tolist()

                    history_rej_query = f"""
                                UPDATE role_rights_history
                                SET status = 'Rejected',
                                    approved_by = '{user}',
                                    updated_date = TO_TIMESTAMP('{currentTS}', 'YYYY-MM-DD HH24:MI:SS')
                                WHERE role_name = '{role_name}' and LOWER(status) = 'waiting for approval'
                            """
                    db.execute_(history_rej_query)

                    if mismatched_role_rights:
                        rights_tuple = tuple(mismatched_role_rights) if len(mismatched_role_rights) > 1 else f"('{mismatched_role_rights[0]}')"
                        
                        logging.info(f'mismatched_role_rights: {mismatched_role_rights}')
                        
                        query = f"""
                            UPDATE role_rights_modifications 
                            SET rejected_comments = '{rejected_comments}' 
                            WHERE role_name = '{role_name}' and status='waiting' and role_rights in {rights_tuple}
                        """
                        db.execute_(query)
                    else:
                        logging.warning(f"No mismatched role rights found for role {role_name}. Skipping update.")

                    query = f"""
                        UPDATE role_rights_modifications 
                        SET status = 'rejected'
                        WHERE role_name = '{role_name}' and status='waiting'
                    """
                    db.execute_(query)
                    response_data = {"flag": True,"message": "Role rejected successfully."}

                except Exception as e:
                    logging.error(f"Error rejecting role {role_name}: {e}")
                    response_data = {"flag": False,"message": "Error in Role rejection"}
            
        except Exception as e:
            logging.info("Something went wrong in updating data:", {e})
            response_data={"flag": False,"message":"Something went wrong"}

        try:
            memory_after = measure_memory_usage()
            memory_consumed = (memory_after - memory_before) / \
                (1024 * 1024 * 1024)
            end_time = tt()
            time_consumed = str(end_time-start_time)
            memory_consumed = f"{memory_consumed:.10f}"
            time_consumed = str(round(end_time-start_time, 3))
        except Exception as e:
            logging.warning("Failed to calc end of ram and time")
            logging.exception("ram calc went wrong")
            memory_consumed = None
            time_consumed = None
        audit_data = {"tenant_id": tenant_id, "user_": user,
                        "api_service": "modify_user", "service_container": "user_management", "changed_data": None,
                        "tables_involved": "","memory_usage_gb": str(memory_consumed), 
                        "time_consumed_secs": time_consumed, "request_payload": json.dumps(data), 
                        "response_data": str(response_data['message']), "trace_id": trace_id, "session_id": session_id,"status":str(response_data['flag'])}
        insert_into_audit(audit_data)

        return jsonify(response_data)


@app.route('/uam_history', methods=['POST', 'GET'])
def uam_history():
    data = request.json
    logging.info(f"data : {data}")
    user = data.get('user', None)
    session_id=data.get('session_id,None')
    flag=data.get('flag',None)
    try:
        memory_before = measure_memory_usage()
        start_time = tt()
    except Exception:
        logging.warning("Failed to start ram and time calc")
        
    
    trace_id = generate_random_64bit_string()
    tenant_id = os.environ.get('TENANT_ID',None)

    attr = ZipkinAttrs(
        trace_id=trace_id,
        span_id=generate_random_64bit_string(),
        parent_span_id=None,
        flags=None,
        is_sampled=False,
        tenant_id=tenant_id
    )

    with zipkin_span(
        service_name='user_management',
        span_name='update_role_rights',
        transport_handler=http_transport,
        zipkin_attrs=attr,
        port=5010,
        sample_rate=0.5
        ):
        try:
            db_config['tenant_id'] = tenant_id
            db = DB('group_access', **db_config)
        except Exception as e:
            logging.error(f"Database connection failed: {e}")
            return {"flag": False, "data": {"message": "Database connection failed."}}
        try:
            active_directory_user_query = f"SELECT ROLE FROM `active_directory` where username = '{user}'"
            active_directory_user_df = db.execute_(active_directory_user_query)
            user_role = active_directory_user_df.iloc[0]['ROLE']
        except:
            user_role = ''
        logging.info(f"###user_role is {user_role}")
        try:
            current_ist = datetime.now(pytz.timezone(tmzone))
            currentTS = current_ist.strftime('%Y-%m-%d %H:%M:%S')
            
            def transform_dormant_history(dormant_history_df):
                final_summary_table = {"headers": [], "rowData": []}

                if dormant_history_df:
                    normalized_records = []
                    
                    for record in dormant_history_df:
                        normalized_record = {}
                        for key, value in record.items():
                            normalized_key = key.lower()  # Normalize keys to lowercase
                            
                            if normalized_key in normalized_record:
                                # If both values are the same, keep one
                                if normalized_record[normalized_key] != value:
                                    # If values are different, keep the latest one (or choose another strategy)
                                    normalized_record[normalized_key] = value
                            else:
                                normalized_record[normalized_key] = value

                        # Convert all keys in normalized_record to uppercase
                        normalized_record_upper = {key.upper(): value for key, value in normalized_record.items()}
                        normalized_records.append(normalized_record_upper)

                    # Convert headers to uppercase
                    final_summary_table["headers"] = [key.upper() for key in normalized_records[0].keys()]
                    final_summary_table["rowData"] = normalized_records  # Store cleaned records

                return {"flag":True,"tableData": final_summary_table}
            # role_rights_query=f"select display_role_rights,new_rights_assigned_status from role_rights where display_role_rights in ('Add User','Modify User','Approve UAM Maker Activity','Reject UAM Maker Activity','UAM Reports','Operation Reports','Add Roles','Modify Roles','View All Queues', 'Modify All Queues') and role_name='{user_role}'"
            # rights_data=db.execute_(role_rights_query).to_dict(orient= 'records')
            # rights_status = {record["display_role_rights"]: record["new_rights_assigned_status"].lower() for record in rights_data}    
            
            # if flag=='uam_dormancy':
            #     if any(rights_status.get(role) == "yes" for role in ['Approve UAM Maker Activity','Reject UAM Maker Activity']):
            #         query = "select * from dormant_rules_history where LOWER(status) <> 'waiting for approval'"
            #         dormant_history_df=db.execute(query).to_dict(orient='records')
            #         logging.info(f"dormant_history_df:{dormant_history_df}")
            #         response_data=transform_dormant_history(dormant_history_df)
            #         logging.info(f"response_data:{response_data}")
            #     if any(rights_status.get(role) == "yes" for role in ['Add User','Modify User','Add Roles','Modify Roles']):
            #         query = "select * from dormant_rules_history"
            #         dormant_history_df=db.execute(query).to_dict(orient='records')
            #         logging.info(f"dormant_history_df:{dormant_history_df}")
            #         response_data=transform_dormant_history(dormant_history_df)
            #         logging.info(f"response_data:{response_data}")
            
            # if flag=='rolemanagement':
            #     if any(rights_status.get(role) == "yes" for role in ['Approve UAM Maker Activity','Reject UAM Maker Activity']):
            #         query = "select * from role_rights_history where LOWER(status) <> 'waiting for approval'"
            #         role_rights_history_df=db.execute(query).to_dict(orient='records')
            #         logging.info(f"role_rights_history_df:{role_rights_history_df}")
            #         response_data=transform_dormant_history(role_rights_history_df)
            #         logging.info(f"response_data:{response_data}")
            #     if any(rights_status.get(role) == "yes" for role in ['Add User','Modify User','Add Roles','Modify Roles']):
            #         query = "select * from role_rights_history"
            #         role_rights_history_df=db.execute(query).to_dict(orient='records')
            #         logging.info(f"role_rights_history_df:{role_rights_history_df}")
            #         response_data=transform_dormant_history(role_rights_history_df)
            #         logging.info(f"response_data:{response_data}")

            # # Fetch user role
            # active_directory_user_query = f"SELECT ROLE FROM active_directory WHERE username = '{user}'"
            # active_directory_user_df = db.execute_(active_directory_user_query)
            # user_role = active_directory_user_df.iloc[0]['ROLE'] if not active_directory_user_df.empty else ''

            # logging.info(f"User role: {user_role}")


            # def transform_dormant_history(dormant_history_df):
            #     if not dormant_history_df:
            #         return {"flag": True, "tableData": {"headers": [], "rowData": []}}

            #     df = pd.DataFrame(dormant_history_df)
            #     df.columns = df.columns.str.upper()  # Convert headers to uppercase
            #     df = df.drop_duplicates()  # Remove duplicate rows

            #     return {"flag": True, "tableData": {"headers": list(df.columns), "rowData": df.to_dict(orient="records")}}

            # def transform_dormant_history(dormant_history_df):
            #     if not dormant_history_df:
            #         return {"flag": True, "tableData": {"headers": [], "rowData": []}}

            #     df = pd.DataFrame(dormant_history_df)

            #     # Normalize column names (case-insensitive) and remove duplicates
            #     df.columns = pd.io.parsers.ParserBase({'names': df.columns})._maybe_dedup_names()
            #     df.columns = df.columns.str.upper()  # Convert column names to uppercase
                
            #     # Remove duplicate rows
            #     df = df.drop_duplicates()

            #     # Convert data to dictionary format
            #     return {"flag": True, "tableData": {"headers": list(df.columns), "rowData": df.to_dict(orient="records")}}

            role_rights_query = f"""
                SELECT display_role_rights, new_rights_assigned_status 
                FROM role_rights 
                WHERE display_role_rights IN ('Add User','Modify User','Approve UAM Maker Activity','Reject UAM Maker Activity',
                                            'UAM Reports','Operation Reports','Add Roles','Modify Roles','View All Queues', 
                                            'Modify All Queues') 
                AND role_name='{user_role}'
            """
            rights_data = db.execute_(role_rights_query).to_dict(orient='records')
            rights_status = {record["display_role_rights"]: record["new_rights_assigned_status"].lower() for record in rights_data}

            # Handle dormancy & role management
            if flag in ('uam_dormancy', 'rolemanagement'):
                status_filter = "LOWER(status) <> 'waiting for approval'" if any(
                    rights_status.get(role) == "yes" for role in ['Approve UAM Maker Activity', 'Reject UAM Maker Activity']
                ) else "1=1"

                table_name = "dormant_rules_history" if flag == 'uam_dormancy' else "role_rights_history"
                query = f"SELECT * FROM {table_name} WHERE {status_filter}"
                df = db.execute(query).to_dict(orient="records")

                response_data = transform_dormant_history(df)

            else:
                response_data = {"flag": False, "message": "Invalid flag"}            

        except Exception as e:
            logging.info("Something went wrong in updating data:", {e})
            response_data={"flag": False,"message":"Something went wrong"}

        try:
            memory_after = measure_memory_usage()
            memory_consumed = (memory_after - memory_before) / \
                (1024 * 1024 * 1024)
            end_time = tt()
            time_consumed = str(end_time-start_time)
            memory_consumed = f"{memory_consumed:.10f}"
            time_consumed = str(round(end_time-start_time, 3))
        except Exception as e:
            logging.warning("Failed to calc end of ram and time")
            logging.exception("ram calc went wrong")
            memory_consumed = None
            time_consumed = None
        # audit_data = {"tenant_id": tenant_id, "user_": user,
        #                 "api_service": "modify_user", "service_container": "user_management", "changed_data": None,
        #                 "tables_involved": "","memory_usage_gb": str(memory_consumed), 
        #                 "time_consumed_secs": time_consumed, "request_payload": json.dumps(data), 
        #                 "response_data": str(response_data['message']), "trace_id": trace_id, "session_id": session_id,"status":str(response_data['flag'])}
        # insert_into_audit(audit_data)

        return jsonify(response_data)