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
            if tenant_id is not None:
                db_config['tenant_id'] = tenant_id
            db = DB('group_access', **db_config)
        except Exception as e:
            logging.error(f"Database connection failed: {e}")
            return {"flag": False, "data": {"message": "Database connection failed."}}

        try:
            current_ist = datetime.now(pytz.timezone(tmzone))
            current_ts = current_ist.strftime('%Y-%m-%d %H:%M:%S')
            if flag == "create":
                new_role_name=data.get('new_role_name', None)
                role_description=data.get('role_description', None)
                type_of_access=data.get('type_of_access',None)
                profile_assigned_to=data.get('profile_assigned_to',None)
                rights_info=data.get('rights_info',{})
                if ((rights_info.get('Add User', False) or rights_info.get('Modify User', False) or rights_info.get('Add Roles', False) or rights_info.get('Modify Roles', False)) and (rights_info.get('Approve UAM Maker Activity', False) or rights_info.get('Reject UAM Maker Activity', False))) or (rights_info.get('View All Queues', False) and rights_info.get('Modify All Queues', False)):
                    return {"flag": False, "message": "Conflict occurs"}                
                try:
                    query="SELECT group_name FROM group_definition"
                    existing_roles = db.execute_(query)
                    if existing_roles:
                        existing_roles = existing_roles['group_name'].tolist()
                    else:
                        existing_roles = []


                except Exception as e:
                    logging.error(f"Query failed,Error:{e}")
                    return {"flag":False,"message":"Error fetching existing roles."}
                if new_role_name in existing_roles:
                    return {"flag": False, "message": "Role already exists."}
                try:
                    query=f"SELECT distinct role_name FROM role_rights_modifications where status='waiting'"
                    verification_roles = db.execute_(query)
                    verification_roles = verification_roles['role_name'].tolist() if verification_roles else []

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
                            ('{new_role_name}','{true_rights_list}', 'Waiting for Approval', '{user}', '', TO_TIMESTAMP('{current_ts}', 'YYYY-MM-DD HH24:MI:SS'))
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
                            'UAMMAKER_DATE': current_ts,
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
                    id_dff=max(id_df)+1 if id_df else 1
                    data_to_insert = {
                        'ID': id_dff,
                        'GROUP_NAME': role_name,
                        'GROUP_DEFINITION': json.dumps({"role": [role_name]}),
                        'GROUP_DEFINITION_TEMPLATE': json.dumps({"roles": ["role"]}),
                        'STATUS': 'enabled',
                        'CREATED_DATE': current_ts,
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
                    query_result = db.execute_(insert_query)
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
                        TO_TIMESTAMP('{current_ts}', 'YYYY-MM-DD HH24:MI:SS') AS UAMCHECKER_DATE,   
                        NULL,
                        ROLE_DESCRIPTION,
                        TYPE_OF_ACCESS,
                        PROFILE_ASSIGNED_TO
                    FROM role_rights_modifications WHERE role_name = '{role_name}'
                    """
                    query_result = db.execute_(query)
                    history_appr_query = f"""
                                UPDATE role_rights_history
                                SET status = 'Accepted',
                                    approved_by = '{user}',
                                    updated_date = TO_TIMESTAMP('{current_ts}', 'YYYY-MM-DD HH24:MI:SS')
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
                                    updated_date = TO_TIMESTAMP('{current_ts}', 'YYYY-MM-DD HH24:MI:SS')
                                WHERE role_name = '{role_name}' and LOWER(status) = 'waiting for approval'
                            """
                    db.execute_(history_rej_query)
                except Exception as e:
                    logging.error(f"Query failed,Error:{e}")
                    return {"flag":False,"message":"Error rejecting role."}

                response_data = {"flag": True,"message": "Role rejected successfully."}
            
        except Exception as e:
            logging.info("Something wrong in updating data:", {e})
            response_data={"flag": False,"message":"check something went wrong"}

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
            logging.exception("ram calc went wrong.")
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
    session_id=data.get('session_id',None)
    flag=data.get('flag',None)
    try:
        memory_before = measure_memory_usage()
        start_time = tt()
    except Exception:
        logging.warning("Failed to start ram and time calc.")
        
    
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
            if tenant_id is not None:
                db_config['tenant_id'] = tenant_id
            db = DB('group_access', **db_config)
        except Exception as e:
            logging.error(f"Database connection failed: {e}")
            return {"flag": False, "data": {"message": "connection failed."}}

        try:
            current_ist = datetime.now(pytz.timezone(tmzone))
            current_ts = current_ist.strftime('%Y-%m-%d %H:%M:%S')
            if flag=='update':
                updated_rights=data.get('updated_rights', {})
                role_name_changes=data.get('role_name_changes',{})
                role_name_map = {str(item): value.strip()for item,value in role_name_changes.items()}
                logging.info(f"role_name_map:{role_name_map}")
                all_updated_roles=[]
                for exist_role,rights_info_df in updated_rights.items():
                    rights_info=rights_info_df.get('rights_assigned',{})
                    all_updated_roles.append(exist_role)
                    if ((rights_info['Add User'] or rights_info['Modify User'] or rights_info['Add Roles'] or rights_info['Modify Roles']) and (rights_info['Approve UAM Maker Activity']  or rights_info['Reject UAM Maker Activity'])) or (rights_info['View All Queues'] and rights_info['Modify All Queues']):
                        return {"flag": False, "message": "Conflict occurs"}
                
                try:
                    query = "SELECT distinct role_name FROM role_rights_modifications WHERE status='waiting'"
                    result = db.execute_(query)
                    waiting_roles = []
                    if isinstance(result, pd.DataFrame) and 'role_name' in result.columns:
                        waiting_roles = result['role_name'].tolist()

                    logging.info(f"waiting_roles:{waiting_roles}")
                except Exception as e:
                    logging.error(f"Error fetching waiting roles: {e}")
                for exist_role,rights_info_df in updated_rights.items():

                    query = f"SELECT DISTINCT status FROM active_directory WHERE role='{exist_role}' and status='enable'"
                    query_result = db.execute_(query)
                    result = query_result["status"].tolist() if isinstance(query_result, pd.DataFrame) else []

                    logging.info(f"user_role_status: {result}")
                    if result!=[]:
                        return jsonify({"flag": False, "message": "Users are in Active state for this Role"})
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
                                'ROLE_RIGHTS': dictvals.get(right, ""),
                                'STATUS': 'waiting',
                                'RIGHTS_ASSIGNED_STATUS': 'Yes' if status else 'No',
                                'UAMMAKER': user,
                                'UAMMAKER_DATE': current_ts,
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
                                    ('{exist_role}','{true_rights_list}', 'Waiting for Approval', '{user}', '', TO_TIMESTAMP('{current_ts}', 'YYYY-MM-DD HH24:MI:SS'))
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
                    query = f"UPDATE role_rights SET old_rights_assigned_status = new_rights_assigned_status,uammaker='{updated_by}',uammaker_date=TO_TIMESTAMP('{updated_date}', 'YYYY-MM-DD HH24:MI:SS'),uamchecker='{user}',uamchecker_date=TO_TIMESTAMP('{current_ts}', 'YYYY-MM-DD HH24:MI:SS') WHERE role_name = '{role}'"
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
                                    updated_date = TO_TIMESTAMP('{current_ts}', 'YYYY-MM-DD HH24:MI:SS')
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

                        query = f"UPDATE group_definition SET status = prev_status,disabled_date=TO_TIMESTAMP('{current_ts}', 'YYYY-MM-DD HH24:MI:SS') WHERE group_name = '{new_role_name}'"
                        db.execute_(query)
                    else:
                        query = f"UPDATE group_definition SET status = prev_status,disabled_date=TO_TIMESTAMP('{current_ts}', 'YYYY-MM-DD HH24:MI:SS') WHERE group_name = '{role}'"
                        db.execute_(query)
                    query = f"UPDATE role_rights_modifications SET status = 'completed' WHERE role_name = '{role}' and status='waiting'"
                    db.execute_(query)
                    response_data= {"flag": True, "message": "Role Approved successfully!"}
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
                                    updated_date = TO_TIMESTAMP('{current_ts}', 'YYYY-MM-DD HH24:MI:SS')
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
                    response_data = {"flag": True,"message": "Role rejected successfully!"}

                except Exception as e:
                    logging.error(f"Error rejecting role {role_name}: {e}")
                    response_data = {"flag": False,"message": "Error in Role rejection"}
            
        except Exception as e:
            logging.info("Something went wrong in updating data:", {e})
            response_data={"flag": False,"message":"Something went wrong in try block"}

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
            
@app.route('/uam_history', methods=['POST', 'GET'])
def uam_history():
    data = request.json
    logging.info(f"data : {data}")
    user = data.get('user', None)
    flag=data.get('flag',None)
    try:
        memory_before = measure_memory_usage()
        start_time = tt()
    except Exception:
        logging.warning("Failed to start ram and time calc!")
        
    
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
            if tenant_id is not None:
                db_config['tenant_id'] = tenant_id
            db = DB('group_access', **db_config)
        except Exception as e:
            logging.error(f"Database connection failed: {e}")
            return {"flag": False, "data": {"message": "Database connection fails."}}
        try:
            active_directory_user_query = f"SELECT ROLE FROM `active_directory` where username = '{user}'"
            active_directory_user_df = db.execute_(active_directory_user_query)
            user_role = active_directory_user_df.iloc[0]['ROLE']
        except Exception:
            user_role = ''
        logging.info(f"###user_role is {user_role}")
        try:            
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
            logging.info("Something went wrong updating data:", {e})
            response_data={"flag": False,"message":"Something went wrong"}
        

        return jsonify(response_data)
@app.route("/show_existing_users", methods=['POST', 'GET'])
def show_existing_users():
    headers=request.headers
    headers_dict={}

    headers=request.headers
    for k,v in headers.items():
        headers_dict[k]=v
    
    
    data = request.json
    logging.info(f'Request data: {data}')
    tenant_id = data.pop('tenant_id', None)

    
    attr = ZipkinAttrs(
            trace_id=generate_random_64bit_string(),
            span_id=generate_random_64bit_string(),
            parent_span_id=None,
            flags=None,
            is_sampled=False,
            tenant_id=tenant_id
        )

    with zipkin_span(
            service_name='user_management',
            zipkin_attrs=attr,
            span_name='show_exisiting_users',
            transport_handler=http_transport,
            sample_rate=0.5
    ) as zipkin_context:
        
        db_config['tenant_id'] = tenant_id
        flag = data.pop('flag', None)
        user = data.get('user','')
        logging.info(f'user is: {user}')
        group_access_db = DB('group_access', **db_config)
        start_point = data.get('start',1)
        end_point = data.get('end',20)
        search_word = data.get('search_word','')
        search_word = search_word.lower()
        
        
        try:
            active_directory_user_query = f"SELECT ROLE FROM `active_directory` where username = '{user}'"
            active_directory_user_df = group_access_db.execute_(active_directory_user_query)
            user_role = active_directory_user_df.iloc[0]['ROLE']
        except Exception:
            user_role = ''
        logging.info(f"###user_role is {user_role}")
        
        
        if flag == 'search':
            try:
                text = data['data'].pop('search_word')
                table_name = data['data'].pop('table_name', 'active_directory')
                start_point = data['data']['start'] - 1
                end_point = data['data']['end']
                header_name = data['data'].get('column', None)
                offset = end_point - start_point
            except Exception:
                traceback.print_exc()
                message = "Input data is missing "
                response_data={"flag": False, "message" : message}    
            
            table_name = 'active_directory'
            columns_list = list(group_access_db.execute_(f"SHOW COLUMNS FROM `{table_name}`")['Field'])
       
            files, total = master_search(tenant_id = tenant_id, text = text, table_name = table_name, start_point = 0, offset = 10, columns_list = columns_list, header_name=header_name)
            
            active_directory_dict = get_attributes_for_active_directory(files, group_access_db)
            
            if end_point > total:
                end_point = total
            if start_point == 1:
                pass
            else:
                start_point += 1
            
            pagination = {"start": start_point, "end": end_point, "total": total}
            
            response_data = {"flag": True, "data": files, "pagination":pagination}
        else:

            #### empty active_directory_df dataframe
            active_directory_df = pd.DataFrame()

            try:
                role_for_count = ""

                role_rights_query=f"select display_role_rights,new_rights_assigned_status from role_rights where display_role_rights in ('Add User','Modify User','Approve UAM Maker Activity','Reject UAM Maker Activity','UAM Reports','Operation Reports','Add Roles','Modify Roles','View All Queues', 'Modify All Queues') and role_name='{user_role}'"
                rights_data=group_access_db.execute_(role_rights_query).to_dict(orient= 'records')
                rights_status = {record["display_role_rights"]: record["new_rights_assigned_status"].lower() for record in rights_data}    

                if any(rights_status.get(role) == "yes" for role in ['Approve UAM Maker Activity','Reject UAM Maker Activity']):
                    role_for_count = "UAM Checker"
                if any(rights_status.get(role) == "yes" for role in ['Add User','Modify User']):
                    role_for_count = "UAM Maker"

                
                try:
                    if user_role == 'UAM Checker' or role_for_count == 'UAM Checker':
                        if search_word != "":
                            active_directory_count = f"""SELECT count(*) as count FROM `active_directory_modifications` ADM 
                                INNER JOIN `active_directory` AD 
                                ON ADM.username = AD.username 
                                WHERE ADM.STATUS NOT IN ('approved','rejected')
                                AND (
                                    LOWER(ADM.username) LIKE '%{search_word}%' 
                                    OR LOWER(ADM.employee_name) LIKE '%{search_word}%' 
                                    OR LOWER(ADM.branch_code) LIKE '%{search_word}%' 
                                    OR LOWER(ADM.branch_name) LIKE '%{search_word}%' 
                                    OR LOWER(ADM.role) LIKE '%{search_word}%' 
                                    OR LOWER(ADM.department_code) LIKE '%{search_word}%' 
                                    OR LOWER(ADM.user_email) LIKE '%{search_word}%'
                                    OR LOWER(ADM.status) LIKE '%{search_word}%'
                                )
                                order by ADM.LAST_UPDATED DESC"""
                            active_directory_count = group_access_db.execute_(active_directory_count)
                        else:
                            active_directory_count = "SELECT count(*) as count FROM `active_directory_modifications` ADM INNER JOIN `active_directory` AD ON ADM.username = AD.username WHERE ADM.STATUS NOT IN ('approved','rejected') order by ADM.LAST_UPDATED DESC"
                            active_directory_count = group_access_db.execute_(active_directory_count)
                    elif user_role == 'UAM Reviewer' or role_for_count == 'UAM Maker':
                        if search_word != "":
                            active_directory_count = f"""SELECT count(*) as count FROM `active_directory` 
                                WHERE STATUS NOT IN ('rejected','closed','waiting')
                                AND (
                                    LOWER(username) LIKE '%{search_word}%' 
                                    OR LOWER(employee_name) LIKE '%{search_word}%' 
                                    OR LOWER(branch_code) LIKE '%{search_word}%' 
                                    OR LOWER(branch_name) LIKE '%{search_word}%' 
                                    OR LOWER(role) LIKE '%{search_word}%' 
                                    OR LOWER(department_code) LIKE '%{search_word}%' 
                                    OR LOWER(user_email) LIKE '%{search_word}%'
                                    OR LOWER(status) LIKE '%{search_word}%'
                                )
                                order by CREATED_DATE DESC"""
                            active_directory_count = group_access_db.execute_(active_directory_count)
                        else:
                            active_directory_count = "SELECT count(*) as count FROM `active_directory` WHERE STATUS NOT IN ('rejected','closed','waiting') order by CREATED_DATE DESC"
                            active_directory_count = group_access_db.execute_(active_directory_count)

                    total = list(active_directory_count['count'])[0]
                except Exception:
                    total = 0
                    logging.warning("####total count of users not getting")
                    pass
                
                offset = start_point-1

                if end_point > total:
                    end_point = total
                paginator_data={"start": start_point,"end": end_point,"total": total}

                
                #changes for UAM Maker and UAM Checker
                if any(rights_status.get(role) == "yes" for role in ['Approve UAM Maker Activity','Reject UAM Maker Activity']):
                    if search_word != "":
                        active_directory_query = f"""SELECT AD.id,AD.USER_AUDIT, ADM.* FROM `active_directory_modifications` ADM 
                            INNER JOIN `active_directory` AD 
                            ON ADM.username = AD.username 
                            WHERE ADM.STATUS NOT IN ('approved','rejected')
                            AND (
                                LOWER(ADM.username) LIKE '%{search_word}%' 
                                OR LOWER(ADM.employee_name) LIKE '%{search_word}%' 
                                OR LOWER(ADM.branch_code) LIKE '%{search_word}%' 
                                OR LOWER(ADM.branch_name) LIKE '%{search_word}%' 
                                OR LOWER(ADM.role) LIKE '%{search_word}%' 
                                OR LOWER(ADM.department_code) LIKE '%{search_word}%' 
                                OR LOWER(ADM.user_email) LIKE '%{search_word}%'
                                OR LOWER(ADM.status) LIKE '%{search_word}%'
                            )
                            order by ADM.LAST_UPDATED DESC 
                            OFFSET {offset} ROWS FETCH NEXT 20 ROWS ONLY"""
                        active_directory_df = group_access_db.execute_(active_directory_query)
                    else:
                        active_directory_query = f"SELECT AD.id,AD.USER_AUDIT, ADM.* FROM `active_directory_modifications` ADM INNER JOIN `active_directory` AD ON ADM.username = AD.username WHERE ADM.STATUS NOT IN ('approved','rejected') order by ADM.LAST_UPDATED DESC OFFSET {offset} ROWS FETCH NEXT 20 ROWS ONLY"
                        active_directory_df = group_access_db.execute_(active_directory_query)

                elif user_role == 'UAM Reviewer':
                    if search_word != "":
                        active_directory_query = f"""SELECT * FROM `active_directory` 
                            WHERE STATUS NOT IN ('rejected','closed','waiting')
                            AND (
                                LOWER(username) LIKE '%{search_word}%' 
                                OR LOWER(employee_name) LIKE '%{search_word}%' 
                                OR LOWER(branch_code) LIKE '%{search_word}%' 
                                OR LOWER(branch_name) LIKE '%{search_word}%' 
                                OR LOWER(role) LIKE '%{search_word}%' 
                                OR LOWER(department_code) LIKE '%{search_word}%' 
                                OR LOWER(user_email) LIKE '%{search_word}%'
                                OR LOWER(status) LIKE '%{search_word}%'
                            )
                            order by CREATED_DATE DESC OFFSET {offset} ROWS FETCH NEXT 20 ROWS ONLY"""
                        active_directory_df = group_access_db.execute_(active_directory_query)
                    else:
                        active_directory_query = f"SELECT * FROM `active_directory` WHERE STATUS NOT IN ('rejected','closed','waiting') order by CREATED_DATE DESC OFFSET {offset} ROWS FETCH NEXT 20 ROWS ONLY"
                        active_directory_df = group_access_db.execute_(active_directory_query)

                    active_directory_query_ = "SELECT ADM.username as username FROM `active_directory_modifications` ADM WHERE ADM.STATUS NOT IN ('approved','rejected')"
                    active_directory_df_ = group_access_db.execute_(active_directory_query_)
                    usernames_set = set(active_directory_df_['username'])
                    active_directory_df['pending'] = active_directory_df['username'].isin(usernames_set)
                    

                if any(rights_status.get(role) == "yes" for role in ['Add User','Modify User']):
                    active_directory_query_ = "SELECT ADM.username as username FROM `active_directory_modifications` ADM WHERE ADM.STATUS NOT IN ('approved','rejected')"
                    active_directory_df_ = group_access_db.execute_(active_directory_query_)

                    if search_word != "":
                        active_directory_query = f"""SELECT * FROM `active_directory` 
                            WHERE STATUS NOT IN ('rejected','closed','waiting')
                            AND (
                                LOWER(username) LIKE '%{search_word}%' 
                                OR LOWER(employee_name) LIKE '%{search_word}%' 
                                OR LOWER(branch_code) LIKE '%{search_word}%' 
                                OR LOWER(branch_name) LIKE '%{search_word}%' 
                                OR LOWER(role) LIKE '%{search_word}%' 
                                OR LOWER(department_code) LIKE '%{search_word}%' 
                                OR LOWER(user_email) LIKE '%{search_word}%'
                                OR LOWER(status) LIKE '%{search_word}%'
                            )
                            order by CREATED_DATE DESC OFFSET {offset} ROWS FETCH NEXT 20 ROWS ONLY"""
                        active_directory_df = group_access_db.execute_(active_directory_query)
                    else:
                        active_directory_query = f"SELECT * FROM `active_directory` WHERE STATUS NOT IN ('rejected','closed','waiting') order by CREATED_DATE DESC OFFSET {offset} ROWS FETCH NEXT 20 ROWS ONLY"
                        active_directory_df = group_access_db.execute_(active_directory_query)

                    usernames_set = set(active_directory_df_['username'])
                    active_directory_df['pending'] = active_directory_df['username'].isin(usernames_set)




                
                

            except Exception:
                traceback.print_exc()
                message = "Could not load from Active Directory"
                response_data = {"flag": False, "message" : message}
            
            
            leaf_nodes=[]
            result = fetch_group_attributes_json(tenant_id, group_access_db = group_access_db)
            
            dropdown_definition = {}
            grp_attributes = result["group_attributes"]
            for grp_attribute in grp_attributes:
                grp_attribute = grp_attributes[grp_attribute]
                for attribute in grp_attribute:
                    dropdown_definition[attribute] = grp_attribute[attribute]

            active_directory_dict = active_directory_df.to_dict(orient= 'records')
            active_directory_dict = get_attributes_for_active_directory(active_directory_dict, group_access_db)
            

                
            
            try:
                field_definition_query = "SELECT * FROM `field_definition` WHERE `status` = 1 and id not in (1,2,7,13,14)"
                field_definition_df = group_access_db.execute_(field_definition_query)
                
                field_definition_df_static = field_definition_df[~field_definition_df['type'].isin(['dropdown','checkbox'])]
                field_definition_df_dynamic = field_definition_df[field_definition_df['type'].isin(['dropdown','checkbox'])]
                  
                field_definition_dict_static = field_definition_df_static.to_dict(orient= 'records')  
                field_definition_dict_dynamic = field_definition_df_dynamic.to_dict(orient= 'records')
                
                for idx, row in enumerate(field_definition_dict_dynamic):
                    if row['unique_name'] in leaf_nodes:
                        field_definition_dict_dynamic[idx]['multiple'] = True
                    else:
                        field_definition_dict_dynamic[idx]['multiple'] = False
            except Exception:
                traceback.print_exc()
                message = "Could not load from Active Directory"
                response_data={"flag": False, "message" : message}

            #User Id and employee code need to be in upper case while entering
            for entry in field_definition_dict_static:
                if entry["id"] == 9 or entry["id"] == 5:
                    entry["isCapital"] = True
            
            
            headers_list = []

            header_list = ["user_email", "role", "username", "employee_code", "employee_name", "branch_code", "branch_name", "department_code", "department_name", "address", "supervisor_code"]
            for header in header_list:
                try:
                    display_name = list(field_definition_df[field_definition_df['unique_name'] == header].display_name)[0]
                    headers_list.append({'display_name': display_name, 'unique_name': header})
                except Exception:
                    traceback.print_exc()
                    logging.error(f"Check configuration for {header}")
                    pass
            query = "SELECT GROUP_NAME,STATUS,PREV_STATUS FROM GROUP_DEFINITION"
            roles = group_access_db.execute_(query)
            roles_df = tuple(roles['group_name'])
            role_status=roles['STATUS']
            prev_role_status=roles['PREV_STATUS']
            logging.info(f"roles_df :{roles_df}")

            disabled_roles_list = roles.loc[roles['STATUS'].str.lower() == 'disabled', 'GROUP_NAME'].tolist()
            dropdown_definition["role"] = [item for item in dropdown_definition["role"] if item not in disabled_roles_list]

            logging.info(f"After removing disabled Roles List: {dropdown_definition}")
            data = {
                "header" : headers_list,
                "rowdata" : active_directory_dict,
                "dropdown_definition": dropdown_definition,
                "field_def_static": field_definition_dict_static,
                "field_def_dynamic": field_definition_dict_dynamic,
                "show_paginator":True,
                "paginator_data":paginator_data,
                "mesh_apps":[],
                "role_management": {
                    "role_creation":{},
                    "roleRights": {}
                }               
            }                

            if user_role == "UAM Maker":
                data['mesh_apps'].append({"name":"Dormancy","target":"login_limit"})
                data["login_validations"]={}
                query="SELECT login_day,first_login_day,no_of_login_attempts FROM dormant_rules where id=1"
                dormant_rules_df=group_access_db.execute(query)
                login_day_limit_df = dormant_rules_df["login_day"].iloc[0]
                first_login_day_limit_df = dormant_rules_df["first_login_day"].iloc[0]
                no_of_login_attempts_df = dormant_rules_df["no_of_login_attempts"].iloc[0]
                data["login_validations"]={
                    "field_mapping":{
                        "login_day_limit":"Login Day Limit",
                        "first_login_day_limit" : "First Login Day Limit",
                        "max_wrong_attempts" : "Max. wrong login attempt count"
                    },
                    "fieldValues":{
                        "login_day_limit":int(login_day_limit_df),
                        "first_login_day_limit":int(first_login_day_limit_df),
                        "max_wrong_attempts":int(no_of_login_attempts_df)
                    }}
            dormancy_count=0
            if user_role == "UAM Checker":
                data['mesh_apps'].append({"name":"Dormancy","target":"change_notification"})
                data["notification_updates"]={}
                query = "SELECT login_day,first_login_day,no_of_login_attempts,new_login_day,new_first_login_day,new_no_of_login_attempts,maker_id,maker_date FROM dormant_rules"
                dormant_rules_df = group_access_db.execute_(query)
                logging.info(f"dormant_rules_df: {dormant_rules_df}")
            
                login_day_limit_df = dormant_rules_df["login_day"].iloc[0]
                first_login_day_limit_df = dormant_rules_df["first_login_day"].iloc[0]
                no_of_login_attempts_df = dormant_rules_df["no_of_login_attempts"].iloc[0]

                new_login_day_limit_df = dormant_rules_df["new_login_day"].iloc[0]
                new_first_login_day_limit_df = dormant_rules_df["new_first_login_day"].iloc[0]
                new_no_of_login_attempts_df = dormant_rules_df["new_no_of_login_attempts"].iloc[0]
                
                uammaker_df = dormant_rules_df["maker_id"].iloc[0]
                uammaker_date_df = dormant_rules_df["maker_date"].iloc[0]
                timestamp_str = uammaker_date_df.strftime("%Y-%m-%d %H:%M:%S")

                datetime_obj = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")
                formatted_date = datetime_obj.strftime('%d-%m-%Y')

                hour = datetime_obj.hour % 12 or 12  
                minute = datetime_obj.minute + datetime_obj.second / 60  
                period = 'PM' if datetime_obj.hour >= 12 else 'AM'

                final_output_date = f"{formatted_date} & {hour + minute / 100:.2f}{period}"            

                notification_updates = {
                    "field_mapping": {
                        "user_name": 'User Name',
                        "date_time": 'Date & Time',
                        "old_value": 'Old Value',
                        "new_value": 'New Value'
                    },
                    "fieldValues": []
                }
            

                if new_login_day_limit_df is not None:
                    notification_updates["fieldValues"].append({
                        "heading": 'Login day limit',
                        "user_name": uammaker_df,
                        "date_time": final_output_date,
                        "old_value": int(login_day_limit_df),
                        "new_value": int(new_login_day_limit_df)
                    })
            
                if new_first_login_day_limit_df is not None:
                    notification_updates["fieldValues"].append({
                        "heading": 'First Login day limit',
                        "user_name": uammaker_df,
                        "date_time": final_output_date,
                        "old_value": int(first_login_day_limit_df),
                        "new_value": int(new_first_login_day_limit_df)
                    })
                if new_no_of_login_attempts_df is not None:
                    notification_updates["fieldValues"].append({
                        "heading": 'Max. wrong login attempt count',
                        "user_name": uammaker_df,
                        "date_time": final_output_date,
                        "old_value": int(no_of_login_attempts_df),
                        "new_value": int(new_no_of_login_attempts_df)
                    })
                data["notification_updates"] = notification_updates
                query = """
                SELECT 
                    (CASE WHEN NEW_LOGIN_DAY IS NOT NULL THEN 1 ELSE 0 END +
                    CASE WHEN NEW_FIRST_LOGIN_DAY IS NOT NULL THEN 1 ELSE 0 END +
                    CASE WHEN NEW_NO_OF_LOGIN_ATTEMPTS IS NOT NULL THEN 1 ELSE 0 END) AS null_count
                FROM dormant_rules
                """
                dormancy_count = group_access_db.execute_(query)['null_count'].iloc[0]

          
            def compare_rights(data1, data2):
                data1_dict = {item["role_rights"]: item["new_rights_assigned_status"] for item in data1}
                data2_dict = {item["role_rights"]: item["rights_assigned_status"] for item in data2}

                comparison_result = []
                for right, old_status in data1_dict.items():
                    if right in data2_dict: 
                        comparison_result.append({
                            "right": right,
                            "old_rights": old_status,
                            "new_rights": data2_dict[right]
                        })

                return comparison_result

            
            query = f"""
                SELECT ROLE_NAME AS role_name, 
                    DISPLAY_ROLE_RIGHTS AS role_rights, 
                    NEW_RIGHTS_ASSIGNED_STATUS AS new_rights_assigned_status, 
                    STATUS AS status 
                FROM ROLE_RIGHTS 
                WHERE ROLE_NAME IN {roles_df}
            """
            role_rights = group_access_db.execute_(query).to_dict(orient="records")
            #for existing roles in uam maker and uam checker
            rights_assigned = {}
            if any(rights_status.get(role) == "yes" for role in ['Add User','Modify User']) or (all(rights_status.get(role) == "no" for role in ['Add User', 'Modify User','Approve UAM Maker Activity','Reject UAM Maker Activity']) and rights_status['Modify Roles']=="yes"):
                role_status_dict = dict(zip(roles_df, role_status))
                for role in roles_df:
                    role_rights_list = [
                        {
                            "role_rights": r["role_rights"], 
                            "new_rights_assigned_status": r["new_rights_assigned_status"]
                        }
                        for r in role_rights if r["role_name"] == role
                    ]
                    rights_assigned = {
                        entry["role_rights"]: entry["new_rights_assigned_status"].lower() == "yes"
                        for entry in role_rights_list
                    }
                    data["role_management"]["roleRights"][role] = {
                        "rights_assigned": rights_assigned,
                        "isRoleEnabled": role_status_dict[role] == "enabled",
                        "showEnableDisable": role not in ["UAM Maker", "UAM Checker"]
                    }
            if any(rights_status.get(role) == "yes" for role in ['Approve UAM Maker Activity','Reject UAM Maker Activity']):
                query = "SELECT DISTINCT role_name FROM role_rights_modifications WHERE status='waiting'"
                waiting_roles = group_access_db.execute_(query)['role_name'].tolist()

                modifications_query = """
                    SELECT role_name, display_role_rights as role_rights, rights_assigned_status, uammaker, uammaker_date 
                    FROM role_rights_modifications 
                    WHERE status='waiting'
                """
                role_rights_modifications = group_access_db.execute_(modifications_query).to_dict(orient="records")
                role_modifications_dict = {}
                
                for mod in role_rights_modifications:
                    role = mod["role_name"]
                    if role not in role_modifications_dict:
                        role_modifications_dict[role] = []
                    role_modifications_dict[role].append(mod)

                prev_role_status_dict = dict(zip(roles_df, prev_role_status))

                new_role_change_query = """
                    SELECT distinct role_name, new_role_name
                    FROM role_rights_modifications 
                    WHERE status='waiting'
                """
                new_role_names = group_access_db.execute_(new_role_change_query).to_dict(orient="records")
                new_role_names_map = {item["role_name"]: item["new_role_name"] for item in new_role_names}
                logging.info(f'new_role_names_map:{new_role_names_map}')

                for role in waiting_roles:
                    if role in roles_df:
                        role_rights_df = [
                            {"role_rights": r["role_rights"], "new_rights_assigned_status": r["new_rights_assigned_status"]}
                            for r in role_rights if r["role_name"] == role
                        ]

                        role_rights_mdf = role_modifications_dict.get(role, [])
                        modified_by = role_rights_mdf[0]['uammaker'] if role_rights_mdf else None
                        modified_date = role_rights_mdf[0]['uammaker_date'] if role_rights_mdf else None

                        comparison = compare_rights(role_rights_df, role_rights_mdf)

                        if role not in data["role_management"]["roleRights"]:
                            data["role_management"]["roleRights"][role] = {"rights_assigned": {}}

                        rights_assigned = {}
                        for right_info in comparison:
                            rights_assigned[right_info["right"]] = {
                                "old": right_info["old_rights"].lower() == "yes",
                                "new": right_info["new_rights"].lower() == "yes"
                            }

                        if "modified_by" not in data["role_management"]["roleRights"][role]:
                            data["role_management"]["roleRights"][role]["modified_by"] = modified_by

                        if "modified_date" not in data["role_management"]["roleRights"][role]:
                            if isinstance(modified_date, datetime):
                                date_str = modified_date.strftime("%Y-%m-%d")
                                time_str = modified_date.strftime("%H:%M:%S")
                            else:
                                date_str, time_str = "", ""

                            data["role_management"]["roleRights"][role]["modified_date"] = date_str
                            data["role_management"]["roleRights"][role]["modified_time"] = time_str

                        data["role_management"]["roleRights"][role].update({
                            "rights_assigned": rights_assigned,
                            "isRoleEnabled": prev_role_status_dict[role] == "enabled",
                            "showEnableDisable": False,
                            "new_role_name":new_role_names_map.get(role,role)
                        })

            #for new role creation in uammaker and checker            
            query_all_rights = "SELECT DISTINCT display_role_rights FROM role_rights"
            query_all_rights_df = group_access_db.execute_(query_all_rights)
            all_rights_rows = query_all_rights_df['display_role_rights'].tolist()
            
            if any(rights_status.get(role) == "yes" for role in ['Add User','Modify User']) or (all(rights_status.get(role) == "no" for role in ['Add User', 'Modify User','Approve UAM Maker Activity','Reject UAM Maker Activity']) and rights_status['Add Roles']=="yes"):
                data["role_management"]["role_creation"]["allRights"] = {}
                for right in all_rights_rows:
                    data["role_management"]["role_creation"]["allRights"][right] = False
            if any(rights_status.get(role) == "yes" for role in ['Approve UAM Maker Activity','Reject UAM Maker Activity']):
                data["role_management"]["role_creation"]["roleRights"] = {}
                query = "SELECT distinct group_name FROM group_definition"
                existing_roles = group_access_db.execute_(query)['group_name'].tolist()
                query = "SELECT distinct role_name FROM role_rights_modifications WHERE status='waiting'"
                waiting_roles = group_access_db.execute_(query)['role_name'].tolist()

                if waiting_roles :  
                    waiting_roles = tuple(waiting_roles) if len(waiting_roles) > 1 else f"('{waiting_roles[0]}')"

                    query = f"""
                        SELECT role_name, display_role_rights, rights_assigned_status, uammaker, uammaker_date,role_description ,profile_assigned_to ,type_of_access 
                        FROM role_rights_modifications 
                        WHERE role_name in {waiting_roles}
                    """
                    rights_rows = group_access_db.execute_(query).to_dict(orient="records")
                    logging.info(f"rights_rows:{rights_rows}")

                    for row in rights_rows:
                        role_name = row['role_name']
                        logging.info(f"#####row{row}")
                        if role_name not in existing_roles:
                            right = row['display_role_rights']
                            status = row['rights_assigned_status']
                            modified_by = row['uammaker']
                            modified_date = row['uammaker_date']
                            role_description=row.get("role_description","")
                            profile_assigned_to=row.get("profile_assigned_to","")
                            type_of_access=row.get("type_of_access","")
                            logging.info(f"%%%%%%{role_description},{profile_assigned_to},{type_of_access}")
                            if role_name not in data["role_management"]["role_creation"]["roleRights"]:
                                data["role_management"]["role_creation"]["roleRights"][role_name] = {
                                    "rights_assigned": {},
                                }

                            data["role_management"]["role_creation"]["roleRights"][role_name]["rights_assigned"][right] = True if status.lower()=="yes" else False

                            if "modified_by" not in data["role_management"]["role_creation"]["roleRights"][role_name]:
                                data["role_management"]["role_creation"]["roleRights"][role_name]["modified_by"] = modified_by
                            
                            if "role_description" not in data["role_management"]["role_creation"]["roleRights"][role_name]:
                                data["role_management"]["role_creation"]["roleRights"][role_name]["role_description"] = role_description

                            if "profile_assigned_to" not in data["role_management"]["role_creation"]["roleRights"][role_name]:
                                data["role_management"]["role_creation"]["roleRights"][role_name]["profile_assigned_to"] = profile_assigned_to
                            
                            if "type_of_access" not in data["role_management"]["role_creation"]["roleRights"][role_name]:
                                data["role_management"]["role_creation"]["roleRights"][role_name]["type_of_access"] = type_of_access

                            if "modified_date" not in data["role_management"]["role_creation"]["roleRights"][role_name]:
                                if isinstance(modified_date, datetime):
                                    date_str = modified_date.strftime("%Y-%m-%d")
                                    time_str = modified_date.strftime("%H:%M:%S")
                                else:
                                    date_str, time_str = "", ""

                                data["role_management"]["role_creation"]["roleRights"][role_name]["modified_date"] = date_str
                                data["role_management"]["role_creation"]["roleRights"][role_name]["modified_time"] = time_str

        
            if any(rights_status.get(role) == "yes" for role in ['Add User','Modify User']) or (all(rights_status.get(role) == "no" for role in ['Add User', 'Modify User','Approve UAM Maker Activity','Reject UAM Maker Activity']) and (rights_status['Modify Roles']=="yes" or rights_status['Add Roles']=="yes")):
                data["role_management"]["isRoleCreation"] = True
                data["role_management"]["showCreate"] = True
                data["role_management"]["role_creation"]["isRoleCreation"] = True
                data["role_management"]["role_creation"]["showCreate"] = True
                data["role_management"]["pageHeading"] = "New Role Creation"
                data['show_delete_user'] = True
                data['show_activate_user'] = True
                data['show_unlock_user'] = True             
                data["role_management"]["role_creation"].update( {
                    "isRightsEditable": True,
                    "showMetaData": False,
                    "showEdit": True,
                    "showUpdate": True
                    }),
                data["role_management"].update({
                    "isRightsEditable": True,
                    "showMetaData": False,
                    "showEdit": True,
                    "showUpdate": True
                } )
            elif user_role =='UAM Reviewer':
                data['show_create_user'] = False
                data['show_edit_user'] = True
                data['show_delete_user'] = False
                data['show_activate_user'] = False
                data['show_unlock_user'] = False
                data['show_info_user'] = True
            if any(rights_status.get(role) == "yes" for role in ['Approve UAM Maker Activity','Reject UAM Maker Activity']):
                len_role_rights_1 = len(data['role_management']['roleRights'])
                len_role_rights_2 = len(data['role_management']['role_creation']['roleRights'])
                role_management_count= len_role_rights_1 + len_role_rights_2
                data['mesh_notifications']={
                    'all':int(dormancy_count)+int(role_management_count),
                    'Dormancy':int(dormancy_count),
                    'Role management':int(role_management_count)}
                data['show_delete_user'] = False
                data['show_activate_user'] = False
                data['show_unlock_user'] = False
                data['show_approval_user'] = True
                data["role_management"]["isRoleCreation"] = False
                data["role_management"]["showCreate"] = False
                data["role_management"]["pageHeading"] = "New Role Creation Details"
                data["role_management"]["role_creation"]["isRoleCreation"] = False
                data["role_management"]["role_creation"]["showCreate"] = False
                data['show_info_user'] = True
                data["role_management"]["role_creation"].update( {
                    "isRightsEditable": False,
                    "showMetaData": True,
                    "showEdit": False,
                    "showUpdate": False
                    }),
                data["role_management"].update({
                    "isRightsEditable": False,
                    "showMetaData": True,
                    "showEdit": False,
                    "showUpdate": False
                } )
            #Rightaccessdata sent to ui
            data['show_create_user']=False
            uam_reports_granted = False
            operation_reports_granted = False
            
            # Handle Role Management additions
            if any(rights_status.get(role) == "yes" for role in ["Add Roles", "Modify Roles",'Approve UAM Maker Activity','Reject UAM Maker Activity']):
                role_management_entry = {"name": "Role management", "target": "role_creation"}
                if role_management_entry not in data["mesh_apps"]:
                    data["mesh_apps"].append(role_management_entry)

            # Determine Approval and Rejection status
            approve_rights = rights_status.get("Approve UAM Maker Activity") == "yes"
            reject_rights = rights_status.get("Reject UAM Maker Activity") == "yes"

            if approve_rights or reject_rights:
                data["role_management"]["role_creation"].update({
                    "showApprove": True,
                    "showAccept": approve_rights,
                    "showReject": reject_rights
                })
                data["role_management"]["showApprove"] = approve_rights
                data["role_management"]["showReject"] = reject_rights
                data.update({'user_approval_info':{
                    'showReject': reject_rights,
                    'showApprove': approve_rights
                }})
                

            # Handle Reports
            uam_reports_granted = rights_status.get("UAM Reports") == "yes"
            operation_reports_granted = rights_status.get("Operation Reports") == "yes"

            # Determine Add User and Modify User status
            add_user_rights = rights_status.get("Add User") == "yes"
            modify_user_rights = rights_status.get("Modify User") == "yes"

            if add_user_rights or modify_user_rights:
                data.update({
                    'show_create_user': add_user_rights,
                    'show_edit_user': True,
                    'create_user_info': {'show_update': modify_user_rights}
                })

            add_role_rights = rights_status.get("Add Roles") == "yes"
            modify_role_rights = rights_status.get("Modify Roles") == "yes"
            if add_role_rights or modify_role_rights or approve_rights or reject_rights:
                data['role_management'].update({
                    'showRoleCreation': add_role_rights or approve_rights or reject_rights,
                    'showExistingRole': modify_role_rights or approve_rights or reject_rights,
                })
            #notification shown in the uamchecker
            if any(rights_status.get(role) == "yes" for role in ['Approve UAM Maker Activity','Reject UAM Maker Activity']):
                len_role_rights_1 = len(data['role_management']['roleRights']) #if data['role_management']['showExistingRole'] else 0
                len_role_rights_2 = len(data['role_management']['role_creation']['roleRights']) #if data['role_management']['showRoleCreation'] else 0
                role_management_count= len_role_rights_1 + len_role_rights_2
                data['mesh_notifications']={
                    'all':int(dormancy_count)+int(role_management_count),
                    'Dormancy':int(dormancy_count),
                    'Role management':int(role_management_count)}
            # Set show_reports flag
            if any(rights_status.get(role) == "yes" for role in ['View All Queues', 'Modify All Queues']):
                data["show_reports"] = False
                data['show_logout'] = False
            else:
                data["show_reports"] = uam_reports_granted or operation_reports_granted
                data['show_logout'] = True

            response_data = {"flag": True, "data" : data}
        
        return response_data
@app.route('/uam_dormancy', methods=['POST', 'GET'])
def uam_dormancy():
    data = request.json
    user = data.get('user',None)
    flag=data.get('flag',None)
    try:
        memory_before = measure_memory_usage()
    except Exception:
        logging.warning("Failed to start ram and time calc!")
    
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
        span_name='uam_dormancy',
        transport_handler=http_transport,
        zipkin_attrs=attr,
        port=5010,
        sample_rate=0.5
        ):
        if tenant_id is not None:
            db_config['tenant_id'] = tenant_id
        db = DB('group_access', **db_config)
        try:
            # Database configuration
            current_ist = datetime.now(pytz.timezone(tmzone))
            current_TS = current_ist.strftime('%Y-%m-%d %H:%M:%S')

            query = "SELECT maker_date FROM dormant_rules"
            maker_date_val = db.execute_(query)["maker_date"].iloc[0]

            if flag == "update":
                field_values = data.get('field_changes')

                new_login_day_limit = field_values.get('login_day_limit', None)
                new_first_login_day_limit = field_values.get('first_login_day_limit', None)
                new_no_of_login_attempts = field_values.get('max_wrong_attempts', None)

                query = "SELECT new_login_day, new_first_login_day, new_no_of_login_attempts FROM dormant_rules"
                values = db.execute_(query)

                new_login_day_limit_df = values["new_login_day"].iloc[0]
                new_first_login_day_limit_df = values["new_first_login_day"].iloc[0]
                new_no_of_login_attempts_df = values["new_no_of_login_attempts"].iloc[0]
                
                update_fields = []
                message_="Already sent for approval"
                if new_login_day_limit is not None and new_login_day_limit_df is None:
                    update_fields.append(f"new_login_day = {new_login_day_limit}")
                elif new_login_day_limit_df is not None:
                    return {"flag": False, "message": message_}
                
                if new_first_login_day_limit is not None and new_first_login_day_limit_df is None:
                    update_fields.append(f"new_first_login_day = {new_first_login_day_limit}")
                elif new_first_login_day_limit_df is not None:
                    return {"flag": False, "message": message_}

                if new_no_of_login_attempts is not None and new_no_of_login_attempts_df is None:
                    update_fields.append(f"new_no_of_login_attempts = {new_no_of_login_attempts}")
                elif new_no_of_login_attempts_df is not None:
                    return {"flag": False, "message": message_}

                if not update_fields:
                    return {"flag": False, "message": message_}
                
                if new_login_day_limit is not None and new_login_day_limit_df is None:
                    new_login_day_limit_history=f"""
                        INSERT INTO dormant_rules_history
                        (Dormant_Headers, Status, Updated_Value, Updated_By, Approved_By, Updated_Date) 
                        VALUES 
                        ('Login Day Limit', 'Waiting for Approval', {new_login_day_limit}, '{user}', '',TO_TIMESTAMP('{current_TS}', 'YYYY-MM-DD HH24:MI:SS'))
                    """
                    db.execute_(new_login_day_limit_history)
                if new_first_login_day_limit is not None and new_first_login_day_limit_df is None:
                    new_first_login_day_limit_history=f"""
                        INSERT INTO dormant_rules_history
                        (Dormant_Headers, Status, Updated_Value, Updated_By, Approved_By, Updated_Date) 
                        VALUES 
                        ('First Login Day Limit', 'Waiting for Approval', {new_first_login_day_limit}, '{user}', '',TO_TIMESTAMP('{current_TS}', 'YYYY-MM-DD HH24:MI:SS'))
                    """
                    db.execute_(new_first_login_day_limit_history)
                if new_no_of_login_attempts is not None and new_no_of_login_attempts_df is None:
                    new_no_of_login_attempts_history=f"""
                        INSERT INTO dormant_rules_history
                        (Dormant_Headers, Status, Updated_Value, Updated_By, Approved_By, Updated_Date) 
                        VALUES 
                        ('Max. wrong login attempt count', 'Waiting for Approval', {new_no_of_login_attempts}, '{user}', '',TO_TIMESTAMP('{current_TS}', 'YYYY-MM-DD HH24:MI:SS'))
                    """
                    db.execute_(new_no_of_login_attempts_history)
                

                update_query = f"UPDATE dormant_rules SET maker_date = TO_TIMESTAMP('{current_TS}', 'YYYY-MM-DD HH24:MI:SS'), maker_id = '{user}', " + ", ".join(update_fields) + " WHERE id = 1"

                updated=db.execute_(update_query)
                if updated:
                    return {"flag": True, "message": "Data Updated Successfully"}
                else:
                    return {"flag": False, "message": "Data not Updated"}
            
            if flag=="approve":
                selected_records = data.get('selected_records')
                for val in range(len(selected_records)):
                    new_val=selected_records[val]['new_value']
                    if selected_records[val]['heading']=='Login day limit':
                        login_day_limit_history_appr=f"""
                            update dormant_rules_history
                            set Status='Approved',Approved_By ='{user}', Updated_Date=TO_TIMESTAMP('{current_TS}', 'YYYY-MM-DD HH24:MI:SS')
                            where Dormant_Headers='Login Day Limit' and Updated_Date=TO_TIMESTAMP('{maker_date_val}', 'YYYY-MM-DD HH24:MI:SS')
                        """
                        db.execute_(login_day_limit_history_appr)
                        a='login_day'
                    if selected_records[val]['heading']=='First Login day limit':
                        frst_login_day_limit_history_appr=f"""
                            update dormant_rules_history
                            set Status='Approved',Approved_By ='{user}', Updated_Date=TO_TIMESTAMP('{current_TS}', 'YYYY-MM-DD HH24:MI:SS')
                            where Dormant_Headers='First Login Day Limit' and Updated_Date=TO_TIMESTAMP('{maker_date_val}', 'YYYY-MM-DD HH24:MI:SS')
                        """
                        db.execute_(frst_login_day_limit_history_appr)
                        a='first_login_day'
                    if selected_records[val]['heading']=='Max. wrong login attempt count':
                        no_of_login_attempts_history_appr=f"""
                            update dormant_rules_history
                            set Status='Approved',Approved_By ='{user}', Updated_Date=TO_TIMESTAMP('{current_TS}', 'YYYY-MM-DD HH24:MI:SS')
                            where Dormant_Headers='Max. wrong login attempt count' and Updated_Date=TO_TIMESTAMP('{maker_date_val}', 'YYYY-MM-DD HH24:MI:SS')
                        """
                        db.execute_(no_of_login_attempts_history_appr)
                        a='no_of_login_attempts'
                        query = f"""
                            UPDATE active_directory 
                            SET 
                                login_attempts = {new_val}
                            WHERE login_attempts != 0
                        """
                        db.execute_(query)
                    query = f"""
                        UPDATE dormant_rules 
                        SET
                            {a}={new_val},
                            new_{a}=NULL
                        WHERE id = 1
                    """
                    update_query=db.execute_(query)
                query = f"""
                        UPDATE dormant_rules 
                        SET 
                            checker_date = TO_TIMESTAMP('{current_TS}', 'YYYY-MM-DD HH24:MI:SS'),
                            checker_id ='{user}'
                        WHERE id = 1
                    """
                db.execute_(query)
                response_data = {"flag": True,"message":"Data Approved Succesfully!."}
                return response_data
            if flag=="reject":
                selected_records = data.get('selected_records')
                rejected_comment=data.get('rejected_comment',None)
                for val in range(len(selected_records)):
                    new_val=selected_records[val]['new_value']
                    if selected_records[val]['heading']=='Login day limit':
                        login_day_limit_history_rej=f"""
                            update dormant_rules_history
                            set Status='Rejected',Approved_By ='{user}', Updated_Date=TO_TIMESTAMP('{current_TS}', 'YYYY-MM-DD HH24:MI:SS')
                            where Dormant_Headers='Login Day Limit' and Updated_Date=TO_TIMESTAMP('{maker_date_val}', 'YYYY-MM-DD HH24:MI:SS')
                        """
                        db.execute_(login_day_limit_history_rej)
                        a='login_day'
                    if selected_records[val]['heading']=='First Login day limit':
                        frst_login_day_limit_history_rej=f"""
                            update dormant_rules_history
                            set Status='Rejected',Approved_By ='{user}', Updated_Date=TO_TIMESTAMP('{current_TS}', 'YYYY-MM-DD HH24:MI:SS')
                            where Dormant_Headers='First Login Day Limit' and Updated_Date=TO_TIMESTAMP('{maker_date_val}', 'YYYY-MM-DD HH24:MI:SS')
                        """
                        db.execute_(frst_login_day_limit_history_rej)
                        a='first_login_day'
                    if selected_records[val]['heading']=='Max. wrong login attempt count':
                        no_of_login_attempts_history_rej=f"""
                            update dormant_rules_history
                            set Status='Rejected',Approved_By ='{user}', Updated_Date=TO_TIMESTAMP('{current_TS}', 'YYYY-MM-DD HH24:MI:SS')
                            where Dormant_Headers='Max. wrong login attempt count' and Updated_Date=TO_TIMESTAMP('{maker_date_val}', 'YYYY-MM-DD HH24:MI:SS')
                        """
                        db.execute_(no_of_login_attempts_history_rej)
                        a='no_of_login_attempts'
                    query = f"""
                        UPDATE dormant_rules 
                        SET 
                            new_{a}=NULL,
                            {a}_rejected_comment='{rejected_comment}'
                        WHERE id = 1
                    """
                    update_query=db.execute_(query)
                query = f"""
                        UPDATE dormant_rules 
                        SET 
                            checker_date = TO_TIMESTAMP('{current_TS}', 'YYYY-MM-DD HH24:MI:SS'),
                            checker_id ='{user}'
                        WHERE id = 1
                    """
                rejected=db.execute_(query)
                if rejected:
                    return {"flag": True,"message":"Data Rejected Succesfully"}
                else:
                    return {"flag": True,"message":"Data not Rejected"}

        except Exception as e:
            logging.info("Something went wrong in updating data:", {e})
            return {"flag": False,"message":"Something went wrong exporting data"}
