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
        pass
    
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
            current_ist = datetime.now(pytz.timezone('Asia/Kolkata'))
            currentTS = current_ist.strftime('%Y-%m-%d %H:%M:%S')
            if flag == "create":
                new_role_name=data.get('new_role_name', None)
                role_description=data.get('role_description', None)
                type_of_access=data.get('type_of_access',None)
                profile_assigned_to=data.get('profile_assigned_to',None)
                rights_info=data.get('rights_info',{})
                if ((rights_info['Add User'] or rights_info['Modify User']) and (rights_info['Approve UAM Maker Activity']  or rights_info['Reject UAM Maker Activity'])) or (rights_info['View All Queues'] and rights_info['Modify All Queues']):
                    return {"flag": False, "message": "Coflict occurs"}
                if not new_role_name:
                    return {"flag": False, "message": "Enter role name"}
                try:
                    query="SELECT group_name FROM group_definition"
                    existing_roles=db.execute_(query)['group_name'].tolist()
                    logging.info(f"existing_roles:{existing_roles}")
                except Exception as e:
                    logging.error(f"Query failed,Error:{e}")
                    return {"flag":False,"message":"Error fetching existing roles."}
                if new_role_name in existing_roles:
                    return {"flag": False, "message": "Role already exists."}
                try:
                    query=f"SELECT distinct role_name FROM role_rights_modifications where status='waiting'"
                    verification_roles=db.execute_(query)['role_name'].tolist()
                    logging.info(f"verification_role:{verification_roles},new_role_name :{new_role_name}")
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
                    except Exception as e:
                        logging.error(f"Query failed ,Error:{e}")
                        return {"flag":False,"message":"Error inserting role rights modifications."}

                response_data= {"flag": True, "message": "Role created successfully! Sent for Approval"}
            
            if flag == "accept":
                role_name = data.get('selected_role', None)
                approval_comments=data.get('approval_comment',None)
                if not role_name:
                    return jsonify({"flag": False, "message": "Role name is required."})

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
        except:
            logging.warning("Failed to calc end of ram and time")
            logging.exception("ram calc went wrong")
            memory_consumed = None
            time_consumed = None
            pass
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
        pass
    
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
            current_ist = datetime.now(pytz.timezone('Asia/Kolkata'))
            currentTS = current_ist.strftime('%Y-%m-%d %H:%M:%S')
            if flag=='update':
                updated_rights=data.get('updated_rights', {})
                role_name_changes=data.get('role_name_changes',{})
                role_name_map = {str(item): value.strip()for item,value in role_name_changes.items()}
                logging.info(f"role_name_map:{role_name_map}")
                for exist_role,rights_info_df in updated_rights.items():
                    rights_info=rights_info_df.get('rights_assigned',{})
                    if (rights_info['Add User'] or rights_info['Modify User']) and (rights_info['Approve UAM Maker Activity']  or rights_info['Reject UAM Maker Activity']) or (rights_info['View All Queues'] and rights_info['Modify All Queues']):
                        return {"flag": False, "message": "Coflict occurs"}
                try:
                    query = f"SELECT distinct role_name FROM role_rights_modifications WHERE status='waiting'"
                    waiting_roles = db.execute_(query)['role_name'].tolist()
                    logging.info(f"waiting_roles:{waiting_roles}")
                except Exception as e:
                    logging.error(f"Error fetching waiting roles: {e}")
                for exist_role,rights_info_df in updated_rights.items():
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

                except Exception as e:
                    logging.error(f"Error approving role {role}: {e}")
                response_data= {"flag": True, "message": "Role Approved successfully."}

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

                    # rights_tuple = tuple(mismatched_role_rights) if len(mismatched_role_rights) > 1 else f"('{mismatched_role_rights[0]}')"

                    # logging.info(f'mismatched_role_rights{mismatched_role_rights}')
                    # query = f"""
                    #     UPDATE role_rights_modifications 
                    #     SET rejected_comments = '{rejected_comments}' 
                    #     WHERE role_name = '{role_name}' and status='waiting' and role_rights in {rights_tuple}
                    # """
                    # db.execute_(query)
                
                    # query = f"""
                    #     UPDATE role_rights_modifications 
                    #     SET status = 'rejected'
                    #     WHERE role_name = '{role_name}' and status='waiting'
                    # """
                    # db.execute_(query)
                except Exception as e:
                    logging.error(f"Error rejecting role {role_name}: {e}")
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
        except:
            logging.warning("Failed to calc end of ram and time")
            logging.exception("ram calc went wrong")
            memory_consumed = None
            time_consumed = None
            pass
        audit_data = {"tenant_id": tenant_id, "user_": user,
                        "api_service": "modify_user", "service_container": "user_management", "changed_data": None,
                        "tables_involved": "","memory_usage_gb": str(memory_consumed), 
                        "time_consumed_secs": time_consumed, "request_payload": json.dumps(data), 
                        "response_data": str(response_data['message']), "trace_id": trace_id, "session_id": session_id,"status":str(response_data['flag'])}
        insert_into_audit(audit_data)

        return jsonify(response_data)


