from django.http import JsonResponse
from django.db import connection
import jwt
import datetime
import pdb
import pymysql
import datetime
import json
import requests
import pytz
from pytz import timezone
from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import status
from django.contrib.sessions.middleware import SessionMiddleware

import os
import sys
import uuid


from aurora_back import settings as aurora_backSettings
sys.path.append(os.path.dirname(aurora_backSettings.__file__))

import pymysql
pymysql.install_as_MySQLdb()
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.hashers import make_password
from django.contrib.auth.hashers import check_password

# 아이의 birthdate check
from datetime import datetime, timedelta

# aws boto3 툴 import
import boto3
# 랜덤 id 생성
import random
import string
import botocore.exceptions

# 모든 api에서 토큰검증
from functools import wraps
# 
from botocore.client import Config

def s3connect():
    service_name = 's3'
    endpoint_url = 'https://kr.object.ncloudstorage.com'
    access_key = '5D04FF07E7BB8C1EFD85'
    secret_key = '0A1DF6FCAA172400D15C650C0E8F1892803C6F71'
    s3 = boto3.client(service_name, endpoint_url=endpoint_url, aws_access_key_id=access_key,aws_secret_access_key=secret_key)
    return s3

def cur_time_asia():
    asia_seoul = pytz.timezone('Asia/Seoul')
    now_asia_seoul = datetime.now(asia_seoul)
    return now_asia_seoul

def hash_pwd_mk(password):
    try:
        hashed_password = make_password(password)
        return hashed_password
    except:
        return print('hash become except')

def hash_pwd_chk(password,hashed_password):
    
    if check_password(password, hashed_password) == True:
        print("비밀번호가 일치합니다.")
        return 'success'
    
    else:
        print("비밀번호가 일치하지 않습니다.")
        return 'false'

def default_result( code,success, msg):
    return {
        'code': code,
        'success': success,
        'message': msg
    }

def sql_executer(sql_context):
    try:
        cur = connection.cursor()
        cur.execute(sql_context)
        rows = cur.fetchall()
        # con ->connection 변경
        connection.commit()
        # DB close
        connection.close()
        return rows
    except Exception as e:
        raise (e)
    finally:
        cur.close()

def validate_date_format(date_string):
    try:
        datetime.strptime(date_string, '%Y-%m-%d')
        return True
    except ValueError:
        return False


def generate_token(user_id):
    # 토큰의 만료 시간 설정
    now_asia_seoul = cur_time_asia()
    expiration_time = now_asia_seoul + timedelta(hours=12)
    # 토큰 페이로드(payload) 설정
    payload = {
        'user_id': user_id,
        'exp': expiration_time
    }
    # 시크릿 키 설정
    secret_key = 'aurora_secret_key'
    # 토큰 생성
    token = jwt.encode(payload, secret_key, algorithm='HS256')
    #request.session['token'] = token
    return token

#토큰을 변수로 받음 - 해당 토큰의 유효성만 검증 (만료시간, 토큰 key 값 검증.)
def verify_token(token):
    SECRET_KEY = 'aurora_secret_key'
    try:
        # 토큰의 유효성 검증 - 해당 키로 파싱되는지.
        decode_token = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        # return decode_token
        return token
    except jwt.ExpiredSignatureError:
        return 'token expired'
    except jwt.InvalidTokenError:
        return False

# 
def token_required(f):
    @wraps(f)
    def decorator(request, *args, **kwargs):
        token = None

        if 'Authorization' in request.headers:
            # 헤더에서 "Bearer <token>" 형식의 값을 가져옵니다.
            auth_header = request.headers['Authorization']
            # 값을 공백으로 분리합니다.
            auth_parts = auth_header.split()
            
            # 첫 번째 부분이 "Bearer"이고, 두 번째 부분(실제 토큰 값)이 있는지 확인합니다.
            if len(auth_parts) == 2 and auth_parts[0].lower() == "bearer":
                token = auth_parts[1]
            else:
                json_response = default_result( 401,False, 'Invalid token')
                return JsonResponse(json_response, status=401)        
        if not token:
            json_response = default_result( 401,False, 'Token is missing')
            return JsonResponse(json_response, status=401)
        
        try:
            # verify_token 함수를 호출하되, 토큰 값 부분만 넘겨줍니다.
            data = verify_token(token)
            if data == 'token expired':
                json_response = default_result( 401,False, 'Token is expired')
                return JsonResponse(json_response, status=401)
            elif data == False:
                json_response = default_result( 401,False, 'Token is invalid')
                return JsonResponse(json_response, status=401)                
        except:
            json_response = default_result( 401,False, 'Token is invalid')
            return JsonResponse(json_response, status=401)
            
        return f(request, *args, **kwargs)

    return decorator

# 

def create_presigned_url(bucket_name, object_name, expiration=3600):
    s3_client = boto3.client('s3', 
                             region_name='kr-standard',
                             endpoint_url='https://kr.object.ncloudstorage.com',
    # access_key = '5D04FF07E7BB8C1EFD85'
    # secret_key = '0A1DF6FCAA172400D15C650C0E8F1892803C6F71'
                             aws_access_key_id='5D04FF07E7BB8C1EFD85',
                             aws_secret_access_key='0A1DF6FCAA172400D15C650C0E8F1892803C6F71',
                             config=Config(signature_version='s3v4'))
    try:
        response = s3_client.generate_presigned_url('get_object',
                                                    Params={'Bucket': bucket_name,
                                                            'Key': object_name},
                                                    ExpiresIn=expiration)
    except Exception as e:
        return None
    return response

@csrf_exempt
@api_view(["POST"])
def login(request):
    if request.method == "POST":

        body = request.body.decode("utf-8")
        data = json.loads(body)
        user_id = data.get("user_id")
        user_pwd = data.get("user_pwd")


        user_check = f''' select user_pwd from au_user where user_id = "{user_id}" '''
        user = sql_executer(user_check)

        user_typeql = f''' select user_type from au_user where user_id = "{user_id}" '''
        userql = sql_executer(user_typeql)
        try:
            user_type = userql[0][0]
            
            if len(user)>0:
                user_hashed_pwd = user[0][0]
                hash_chk = hash_pwd_chk(user_pwd,user_hashed_pwd)

                SECRET_KEY = 'aurora_secret_key'
                token = generate_token(user_id)
                token = verify_token(token)

                if token == 'token expired':
                    response_data = {
                    'code':401,
                    'success': False,
                    'message': 'token expired'
                    }
                    json_response = response_data
                    return Response(json_response, status = 401)
                elif token == False:
                    response_data = {
                    'code': 403,
                    'success': False,
                    'message': 'token False'
                    }
                    json_response = response_data
                    return Response(json_response, status = 403)
                else:
                    if hash_chk == 'false':
                        response_data = {
                        'code': 403,   
                        'success': False,
                        'message': 'pwd False'
                        # ,# 'user_hashed_pwd': user_hashed_pwd 
                        }
                        json_response = response_data
                        return Response(json_response, status = 403)
                    else:
                        now_asia_seoul = cur_time_asia()
                        response_data = {
                            'code' : 200,
                            'success': True,
                            'message': 'login succeed',
                            'data' : {'user_token': token,
                            'user_type': user_type
                            # 'pwd_check': hash_chk
                            }

                            }
                        update_loginql = f''' UPDATE au_user set login_date = "{now_asia_seoul}" where user_id = "{user_id}" '''
                        updateql = sql_executer(update_loginql)
                        json_response = response_data
                        return Response(json_response, status = status.HTTP_200_OK)
            else:
                return JsonResponse({
                    'code' : 401,
                    'success': False,
                    'message': 'Invalid login credentials',
                    'user_type' : user_type
                    }, 
                    status=401)
        except:
            return JsonResponse({
                'code' : 401,
                'success': False,
                'message': 'Invalid login ID',
                }, 
                status=401)            


@csrf_exempt
@api_view(["POST"])
def signup(request):

    asia_seoul = pytz.timezone('Asia/Seoul')
    now_asia_seoul = datetime.now(asia_seoul)

    body = request.body.decode("utf-8")
    data = json.loads(body)
    user_id = data.get("user_id")
    user_pwd = data.get("user_pwd")
    user_type = data.get("user_type")
    user_phone = data.get("user_phone")
    
    if user_type == "parent":

        try:
            user_agreement = data.get("user_agreement")

            user_pwd = hash_pwd_mk(user_pwd)      
            user_insert_ql = f'''  INSERT INTO au_user (user_id, user_pwd, user_type, user_phone) VALUES ("{user_id}", "{user_pwd}", "{user_type}", "{user_phone}") '''
            insertql = sql_executer(user_insert_ql)
            
            for agreement in user_agreement:
                agreement_num = agreement.get("agreement_num")
                agreement_ver = agreement.get("agreement_ver")
                agreement_yn = agreement.get("agreement_yn")
                agreement_type = agreement.get("agreement_type")
                agreeinsert = f'''  INSERT INTO au_agreements (user_id, agreement_type ,agreement_yn,agreement_num, agreement_ver ,  agreedttm) VALUES ("{user_id}", "{agreement_type}", "{agreement_yn}", "{agreement_num}","{agreement_ver}","{now_asia_seoul}") '''
                insertql = sql_executer(agreeinsert)
            #if user table id 가 겹치지 않는다면 , agreeement table 에 insert 

            print("user is parent")
            response_data = {
                    "code": 200,
                    "success": True,
                    "message": "insert parent successs",
                    }
            json_response = response_data
            return Response(json_response, status = status.HTTP_200_OK)
        except Exception as e:
            excpt = (f"An error occured: {e}")
            return JsonResponse({
                'code' : 401,
                'success': False,
                'message': excpt
                },
                status=401)

        
    elif user_type == "evaluator":
        user_pwd = hash_pwd_mk(user_pwd)   
        user_email = data.get("user_email")
        user_name = data.get("user_name")
        user_approval = "N" # 기본 approaval 은 N 입니다. 
        try:
            user_insert_ql = f'''  INSERT INTO au_user (user_id, user_pwd, user_type, user_phone,user_email,user_name,user_approval) VALUES ("{user_id}", "{user_pwd}", "{user_type}", "{user_phone}","{user_email}","{user_name}","N") '''
            insertql = sql_executer(user_insert_ql)
            print("user is evaluator")
            response_data = {
                    "code":200,
                    "success": True,
                    "message": "insert evaluator success",
                    }
            json_response = response_data
            return Response(json_response, status = status.HTTP_200_OK)
        except Exception as e:
            excpt = (f"An error occured: {e}")
            return JsonResponse({
                'code' : 401,
                'success': True,
                'message': excpt
                },
                status=401)

    elif user_type == "admin":
        user_email = data.get("user_email")
        user_name = data.get("user_name")
        user_pwd = "1111"
        user_pwd = hash_pwd_mk(user_pwd)

        try:
            user_insert_ql = f'''  INSERT INTO au_user (user_id, user_pwd, user_type, user_phone,user_email,user_name) VALUES ("{user_id}", "{user_pwd}", "{user_type}", "{user_phone}","{user_email}","{user_name}") '''
            insertql = sql_executer(user_insert_ql)

            #초기 비밀번호 1111
            response_data = {
                    "code": 200,
                    "success": True,
                    "message": "insert admin success",
                    }
            json_response = response_data
            return Response(json_response, status = status.HTTP_200_OK)
        except Exception as e:
            excpt = (f"An error occured: {e}")
            return JsonResponse({
                'code' : 401,
                'success': False,
                'message': excpt
                },
                status=401)

    else:
        print("invalid user type")
        return JsonResponse({
            'code':401,
            'error': 'invalid user_type ql'
            },
                status=401)

@csrf_exempt
@token_required
@api_view(["POST"])
def password_reset(request):

    body = request.body.decode("utf-8")
    data = json.loads(body)
    user_id = data.get("user_id")
    user_type = data.get("user_type")

    user_typeql = f''' select user_type from au_user where user_id = "{user_id}" '''
    userql = sql_executer(user_typeql)

    if len(userql)>0 and user_type == userql[0][0]:        
        hashed_password = hash_pwd_mk('1111')
        update_resetql = f''' UPDATE au_user set user_pwd = "{hashed_password}" where user_id = "{user_id}" '''
        updateql = sql_executer(update_resetql)


        json_response = default_result('200','success','password successfully reset')
        return Response(json_response, status = status.HTTP_200_OK)

    else:

        json_response = default_result('400',False,'password reset False')
        return Response(json_response, status = status.HTTP_200_OK)

@csrf_exempt
@token_required
@api_view(["POST"])
def password_change(request):
    body = request.body.decode("utf-8")
    data = json.loads(body)
    user_id = data.get("user_id")
    user_cur_pwd = data.get("user_cur_pwd")
    user_new_pwd = data.get("user_new_pwd")

    user_check = f''' select user_pwd from au_user where user_id = "{user_id}" '''
    user_check_col = sql_executer(user_check)
    if len(user_check_col)>0:
        cur_pwd = user_check_col[0][0] #저장된 해시 비밀번호를 불러오기. - 회원가입떄 비번은 해시되서 저장됩니다. 

        hash_chk = hash_pwd_chk(user_cur_pwd,cur_pwd)         # 그냥패스워드랑 해시 패스워드(DB) 비교해야되는데, 이미 해시 패스워드를 저장합니다. 
        if hash_chk == 'success':
            user_new_pwd = hash_pwd_mk(user_new_pwd)
            update_resetql = f''' UPDATE au_user set user_pwd = "{user_new_pwd}" where user_id = "{user_id}" '''
            updateql = sql_executer(update_resetql)
        else:
            json_response = default_result( 401,False, 'matching user does not exist ')
            return Response(json_response, status = '401') 

        json_response = default_result(200,True,'password successfully change')
        return Response(json_response, status = status.HTTP_200_OK) 
    else:
        json_response = default_result(401,False, 'matching user does not exist ')
        return Response(json_response, status = '401') 

@csrf_exempt
@token_required
@api_view(["POST"])
def delete_user(request):
    asia_seoul = pytz.timezone('Asia/Seoul')
    now_asia_seoul = datetime.now(asia_seoul)

    body = request.body.decode("utf-8")
    data = json.loads(body)
    user_id = data.get("user_id")
    user_type = data.get("user_type")

    #유저 존재 확인
    user_check = f''' select user_id from au_user where user_id = "{user_id}" '''
    user_check_col = sql_executer(user_check)
    if len(user_check_col)>0:
        delete_useql = f''' Delete from au_user where user_id = "{user_id}" '''
        deleteql = sql_executer(delete_useql)

        json_response = default_result(200,True,'user successfully deleted')
        return Response(json_response, status = status.HTTP_200_OK)
    else:
        json_response = default_result(401,False, 'matching user does not exist ')
        return Response(json_response, status = '401')


@csrf_exempt
@token_required
@api_view(["POST"])
def admin_list(request): 
    body = request.body.decode("utf-8")
    data = json.loads(body)
    user_search = data.get("user_search")
    user_type = data.get("user_type")

    admin_listql = f''' select user_id, user_name, create_date, login_date from au_user where (user_id like "%{user_search}%" or user_name like "%{user_search}%") and user_type = "{user_type}" '''
    admin_list = sql_executer(admin_listql)

    response_data = {
                    "code": 200,
                    "success": True,
                    "message": "success",
                    "data" : {"adminlist": admin_list}
                    }
    json_response = response_data
    return Response(json_response, status= status.HTTP_200_OK)
    # 쿼리 튜닝하기 
    # 

@csrf_exempt
@token_required
@api_view(["POST"])
def admin_create(request):
    body = request.body.decode("utf-8")
    data = json.loads(body)
    user_id = data.get("user_id")
    user_name = data.get("user_name")
    user_phone = data.get("user_phone")
    user_email = data.get("user_email")
    user_pwd = '123456'
    hashed_pwd = hash_pwd_mk(user_pwd)

    try:
        admin_insert = f''' INSERT INTO au_user (user_id, user_name, user_type, user_phone,user_email,user_pwd) VALUES ("{user_id}","{user_name}" ,"admin", "{user_phone}","{user_email}", "{hashed_pwd}") '''
        insertql = sql_executer(admin_insert)
        json_response = default_result(200,True, 'admin create success')        
        return Response(json_response, status= status.HTTP_200_OK)

    except:
        json_response = default_result(401,False, 'admin create False')
        return Response(json_response, status = '401')

@csrf_exempt
@token_required
@api_view(["POST"])
def admin_detail_search(request):
    body = request.body.decode("utf-8")
    data = json.loads(body)
    user_id = data.get("user_id")
    user_type = data.get("user_type")
    try:
        admin_listql = f''' select user_id, user_name, user_email, user_phone from au_user where user_id = "{user_id}"  and user_type = "{user_type}" '''
        admin_list = sql_executer(admin_listql)
        user_name = admin_list[0][1]
        user_email = admin_list[0][2]
        user_phone = admin_list[0][3]

        response_data = {
                    "code": 200, 
                    "success": True,
                    "message" : "admin_detail_list get success",
                    "data" : {"user_name": user_name,
                    "user_email": user_email,
                    "user_phone": user_phone}
                    }
        json_response = response_data
        return Response(json_response, status= status.HTTP_200_OK)
    except:
        json_response = default_result(401, False, 'admin search fail')
        return Response(json_response, status = '401')
    

@csrf_exempt
@token_required
@api_view(["POST"])
def admin_detail_revise(request):   
    now_asia_seoul = cur_time_asia()
    body = request.body.decode("utf-8")
    data = json.loads(body)
    user_id = data.get("user_id")
    user_type = data.get("user_type")
    user_name = data.get("user_name")
    user_phone = data.get("user_phone")
    user_email = data.get("user_email")


    try:
        update_ql = f''' UPDATE au_user set user_name = "{user_name}", user_phone = "{user_phone}", user_email = "{user_email}" where user_id = "{user_id}" '''
        update_ql_com = sql_executer(update_ql)

        response_data = default_result(200,True,'user successfully updated')
        json_response = response_data
        return Response(json_response, status= status.HTTP_200_OK)
    except:

        response_data = default_result(401, False, 'user update fail')
        json_response = response_data
        return Response(json_response, status = '401')
    

@csrf_exempt
@token_required
@api_view(["POST"])
def parent_list(request):
    now_asia_seoul = cur_time_asia()
    body = request.body.decode("utf-8")
    data = json.loads(body)
    user_id = data.get("user_id")
    user_type = data.get("user_type")

    parent_dicts = []
    try:
        parent_listql = f''' select user_id, user_name, create_date, login_date from au_user where (user_id like "%{user_id}%") and user_type = "{user_type}" '''
        parent_qlcom = sql_executer(parent_listql)

        for record in parent_qlcom:
            user_id, user_name, create_date, login_date = record
            parent_dict = {
                "user_id": user_id,
                "user_name": user_name,
                "create_date": create_date,
                "login_date": login_date
            }
            parent_dicts.append(parent_dict) # 딕셔너리를 리스트에 추가

        response_data = {
                    "code": 200,
                    "success": True,
                    "message": "user select success",
                    "data": {"parent_list" : parent_dict}
                    }
        
    except:
        response_data = {
                    "code": 401,
                    "success": False,
                    "message" : "parent select fail"
                    }
        
        json_response = response_data
        return Response(json_response, status = '401')

    json_response = response_data
    return Response(json_response, status= status.HTTP_200_OK)

@csrf_exempt
@token_required
@api_view(["POST"])
def parent_detail_search(request):
    body = request.body.decode("utf-8")
    data = json.loads(body)
    user_id = data.get("user_id")
    user_type = data.get("user_type")

    parent_listql = f''' select user_id, user_name, create_date, login_date from au_user where (user_id like "%{user_id}%") and user_type = "{user_type}" '''
    parent_list = sql_executer(parent_listql)
    try:
        user_name = parent_list[0][1]
        create_date = parent_list[0][2]
        login_date = parent_list[0][3]

        response_data = {
                        "code": 200,
                        "success": True,
                        "message": "parent detail search success",
                        "data" :{ "user_id": user_id,
                                "user_name": user_name,
                                "create_date": create_date,
                                "login_date": login_date,}
                    }
        json_response = response_data
        return Response(json_response, status= status.HTTP_200_OK)
    except:
        json_response = default_result(400,False,'user does not exist')
        return Response(json_response, status= 400)        


@csrf_exempt
@token_required
@api_view(["POST"])
def evaluator_list(request):  
    now_asia_seoul = cur_time_asia()
    body = request.body.decode("utf-8")
    data = json.loads(body)
    user_search = data.get("user_search")
    user_approval = data.get("user_approval")     # user_approval ('Y','N')
    eval_listql = f''' select user_id, user_name, create_date, login_date, user_approval from au_user where (user_id like "%{user_search}%" or user_name like "%{user_search}%") and user_approval = "{user_approval}" '''
    eval_list = sql_executer(eval_listql)
    response_data = {
                    "success": True,
                    "message": "evaluator list successfully get",
                    "data": {"eval_list": eval_list}
                    }
    json_response = response_data
    return Response(json_response, status= status.HTTP_200_OK)

@csrf_exempt
@token_required
@api_view(["POST"])
def evaluator_detail_search(request):  
    now_asia_seoul = cur_time_asia()
    body = request.body.decode("utf-8")
    data = json.loads(body)
    user_id = data.get("user_id")
    try:
        admin_listql = f''' select user_id, user_name, user_email, user_phone from au_user where user_id = "{user_id}" '''
        admin_list = sql_executer(admin_listql)
        user_name = admin_list[0][1]
        user_email = admin_list[0][2]
        user_phone = admin_list[0][3]

        response_data = {
                    "code" : 200,
                    "success": True,
                    "data" : {"user_name": user_name,
                    "user_email": user_email,
                    "user_phone": user_phone}
                    }
        json_response = response_data
        return Response(json_response, status= status.HTTP_200_OK)
    except:
        response_data = default_result(False, 'admin search fail')
        json_response = response_data
        return Response(json_response, status = '401')


@csrf_exempt
@token_required
@api_view(["POST"])
def evaluator_detail_revise(request): 
    now_asia_seoul = cur_time_asia()
    body = request.body.decode("utf-8")
    data = json.loads(body)
    user_id = data.get("user_id")
    user_name = data.get("user_name")
    user_phone = data.get("user_phone")
    user_email = data.get("user_email")
    user_approval = data.get("user_approval")

    try:
        update_ql = f''' UPDATE au_user set user_name = "{user_name}", user_phone = "{user_phone}", user_email = "{user_email}", user_approval = "{user_approval}" where user_id = "{user_id}" '''
        update_ql_com = sql_executer(update_ql)
 
        response_data = default_result(200, True, 'user successfully updated')
        json_response = response_data
        return Response(json_response, status= status.HTTP_200_OK)
    except:

        response_data = default_result(401, False, 'user update fail')
        json_response = response_data
        return Response(json_response, status = '401')

@csrf_exempt
@token_required
@api_view(["POST"])
def child_list(request):
    now_asia_seoul = cur_time_asia()        
    body = request.body.decode("utf-8")
    data = json.loads(body)
    user_id = data.get("user_id")
    child_dicts = []
    try:
        select_child_ql = f''' select child_name,birth_date,gender,child_id from au_child where user_id = "{user_id}" '''
        child_ql_com = sql_executer(select_child_ql)
# ################
        for record in child_ql_com:
            child_name = record[0]
            birth_date = record[1]
            gender = record[2]
            child_id = record[3]
            child_dict = {"child_name": child_name,
                          "birth_date": birth_date,
                          "gender": gender,
                          "child_id": child_id
                          }
            child_dicts.append(child_dict)
# 이름,생년, 성별, 자녀아이디
        response_data = {
                    "code": 200,
                    "success": True,
                    "message" : "child successfully get",
                    "data" : {"child_list" : child_dicts}
                    }
        json_response = response_data
        return Response(json_response, status= status.HTTP_200_OK)
    except:
        response_data = {
                    "code": 401,
                    "success": False,
                    "message" : "child select fail"
                    }
        json_response = response_data

        return Response(json_response, status = '401')

@csrf_exempt
@token_required
@api_view(["POST"])
def child_create(request):
    now_asia_seoul = cur_time_asia()
    body = request.body.decode("utf-8")
    data = json.loads(body)
    user_id = data.get("user_id")
    child_name = data.get("child_name")
    birth_date = data.get("birth_date")
    gender = data.get("gender")
    child_id = str(uuid.uuid4())
    form_date = validate_date_format(birth_date)
    if form_date == True:
        try:
            insert_ql = f''' INSERT INTO au_child (child_name, birth_date, child_id, gender, user_id ) VALUES ("{child_name}", '{birth_date}', "{child_id}", "{gender}", "{user_id}"); '''
            insert_ql_com = sql_executer(insert_ql)

            response_data = default_result(200, True, 'child successfully created')
            json_response = response_data
            return Response(json_response, status= status.HTTP_200_OK)
        
        except:

            response_data = default_result(401, False, 'child create fail')
            json_response = response_data
            return Response(json_response, status = '401')
    else:
        response_data = default_result(401, False, 'invalid date format')        
        return Response(json_response, status = '401')
    
@csrf_exempt
@token_required
@api_view(["POST"])
def child_detail_search(request):
# 자녀프로필 조회
    now_asia_seoul = cur_time_asia()
    body = request.body.decode("utf-8")
    data = json.loads(body)
    user_id = data.get("user_id")
    child_name = data.get("child_name")

    try:
        select_child_ql = f''' select birth_date, gender from au_child where user_id = "{user_id}" and child_name = "{child_name}" '''
        child_ql_com = sql_executer(select_child_ql)
        birth_date = child_ql_com[0][0]
        gender = child_ql_com[0][1]        
        response_data = {
                    "code":200,
                    "success": True,
                    "message" : "child successfully get",
                    "data" : {"birth_date" : birth_date,
                    "gender" : gender}
                    }
        json_response = response_data
        return Response(json_response, status= status.HTTP_200_OK)
    except:
        response_data = {
                    "code":401,
                    "success": False,
                    "message" : "child unsuccessfully get"
                    }
        json_response = response_data
        return Response(json_response, status = '401')

@csrf_exempt
@token_required
@api_view(["POST"])
# 자녀 프로필 수정
def child_detail_revise(request):
    body = request.body.decode("utf-8")
    data = json.loads(body)
    child_name = data.get("child_name")
    child_id = data.get("child_id")
    gender = data.get("gender")
    
    try:
        update_ql = f''' UPDATE au_child set child_name = "{child_name}", gender = "{gender}" where child_id = "{child_id}" '''
        update_ql_com = sql_executer(update_ql)

        response_data = default_result(200, True, 'user successfully updated')
        json_response = response_data
        return Response(json_response, status= status.HTTP_200_OK)
    
    except:
        response_data = default_result(401, False, 'user update fail')
        json_response = response_data
        return Response(json_response, status = '401')
    



@csrf_exempt
@token_required
@api_view(["POST"])
def asset_list(request):
    asset_list = []
    asset_ql = f''' select asset_id, createdttm, asset_desc, asset_volume,asset_apply from au_asset '''
    asset_tuple = sql_executer(asset_ql)
    for record in asset_tuple:
        asset_id, createdttm, asset_desc, asset_volume, asset_apply = record
        asset_dict = {
            "asset_id": asset_id,
            "createdttm": createdttm,
            "asset_desc": asset_desc,
            "asset_volume": asset_volume,
            "asset_apply": asset_apply,
        }
        asset_list.append(asset_dict) # 딕셔너리를 리스트에 추가

    response_data = {
                    "code": 200,
                    "success": True,
                    "message": "success",
                    "data" : {"asset_list": asset_list}
                    }

    response_data = default_result(200, True, 'user successfully updated')
    json_response = response_data
    return Response(json_response, status= status.HTTP_200_OK)


@csrf_exempt
@token_required
@api_view(["POST"])
def delete_asset(request):
    asia_seoul = pytz.timezone('Asia/Seoul')
    body = request.body.decode("utf-8")
    data = json.loads(body)
    asset_id = data.get("asset_id")
    asset_apply = data.get("asset_apply")
    asset_check = f''' select asset_name from au_asset where asset_id = "{asset_id}" '''
    asset_check_col = sql_executer(asset_check)
    if len(asset_check_col)>0:
        try:
            s3 = s3connect()
            bucket_name = 'aurora'
            object_name = f''' application_file/asset/"{asset_check_col[0][0]}" ''' #asset_check_col 은 에셋 파일이름입니다. .zip 파일. 
            s3.delete_object(Bucket=bucket_name, Key=object_name)
            # DB delete 추가             
            delete_assetql = f''' Delete from au_asset where asset_id = "{asset_id}" '''
            deleteql = sql_executer(delete_assetql)

            json_response = default_result(200,True,'asset successfully deleted')
            return Response(json_response, status = status.HTTP_200_OK)
        except:
            json_response = default_result(401,False, 'delete asset error ')
            return Response(json_response, status = '401')
    else:
        json_response = default_result(401,False, 'matching user does not exist ')
        return Response(json_response, status = '401')

@csrf_exempt
@token_required
@api_view(["POST"])
def asset_upload(request):
    now_asia_seoul = cur_time_asia()
    endpoint_url = 'https://kr.object.ncloudstorage.com'

    access_key = '5D04FF07E7BB8C1EFD85'
    secret_key = '0A1DF6FCAA172400D15C650C0E8F1892803C6F71'
    service_name = 's3'

    # s3 = boto3.client(service_name, endpoint_url=endpoint_url, aws_access_key_id=access_key,aws_secret_access_key=secret_key)
    s3 = s3connect()
    bucket_name = 'aurora'

    if 'zipfile' in request.FILES:
        file = request.FILES['zipfile']
        if file.name.endswith('.zip'):
            bucket_name = 'aurora'
            file_size = file.size
            file_size_mb = file_size / (1024 * 1024)
            file_name_in_s3 = 'application_file/asset/' + file.name
            try:
                s3.upload_fileobj(file, bucket_name, file_name_in_s3)

            # 업로드, 
                current_time = now_asia_seoul.strftime("%Y%m%d%H%M%S")  # 현재 시간을 문자열로 변환                    
                random_alphabet = ''.join(random.choice(string.ascii_letters) for _ in range(5))  # 랜덤 알파벳 5개 생성
                asset_id = 'A' + current_time + random_alphabet
                s3_url = f''' https://kr.object.ncloudstorage.com/"{bucket_name}"/"{file_name_in_s3}" '''

            # DB 인서트
                json_data = request.POST.get('json_data', '{}')
                data = json.loads(json_data)
                asset_desc = data.get("asset_desc")
                # 
                try:
                    asset_insert = f''' insert into au_asset (asset_id, asset_name,createdttm, asset_desc, asset_volume, asset_apply, asset_s3_url) VALUES ("{asset_id}", "{file.name}" ,"{now_asia_seoul}", "{asset_desc}", "{file_size_mb}","N", "{s3_url}" ) '''
                    asset_insert_ql = sql_executer(asset_insert)
                    json_response = default_result(200,True,'asset successfully insertted')
                    return Response(json_response, status = status.HTTP_200_OK)
                except:
                    json_response = default_result(400,False,'asset insertted False')
                    return Response(json_response, status = '401')
# rebuild botocore error message
            except botocore.exceptions.BotoCoreError as e:
                json_response = default_result(400, False, 'S3 insert failed: {}'.format(str(e)))
                return Response(json_response, status='401')

            except botocore.exceptions.ClientError as e:
                error_code = e.response['Error']['Code']
                error_message = e.response['Error']['Message']
                json_response = default_result(400, False, 'S3 insert failed: {} - {}'.format(error_code, error_message))
                return Response(json_response, status='401')

            except Exception as e:
                json_response = default_result(400, False, 'S3 insert failed: {}'.format(str(e)))
                return Response(json_response, status='401')
            except:
                json_response = default_result(400,False,'asset s3 insert False')
                return Response(json_response, status = '401')            
    else:
        json_response = default_result(400,False,'file is not zip file')
        return Response(json_response, status = '401')

@csrf_exempt
@token_required
@api_view(["POST"])
# 에셋 적용.
def asset_revise(request):
    now_asia_seoul = cur_time_asia()
    body = request.body.decode("utf-8")
    data = json.loads(body)
    asset_id = data.get("asset_id")

    try:

        update_ql = f''' UPDATE au_asset set asset_apply = "N" '''
        update_ql_com = sql_executer(update_ql)

        update_ql = f''' UPDATE au_asset set asset_apply = "Y" where asset_id = "{asset_id}" '''
        update_ql_com = sql_executer(update_ql)

        response_data = default_result(200, True, 'user successfully updated')
        json_response = response_data
        return Response(json_response, status= status.HTTP_200_OK)
    
    except:
        response_data = default_result(401, False, 'user update fail')
        json_response = response_data
        return Response(json_response, status = '401')

#  앱 


#  지도안 


# 콘텐츠 임시 변경

import base64

@csrf_exempt
@token_required
@api_view(["POST"])
def content_upload(request):
    now_asia_seoul = cur_time_asia()
    body = request.body.decode("utf-8")
    data = json.loads(body)
    s3 = s3connect()
    bucket_name = 'aurora'
    content_title = data.get("content_title")
    user_id = data.get("user_id")
    child_id = data.get("child_id") #못찾으면 백엔드에서 select 문으로 찾기. 
    child_name = data.get("child_name")
    content_id = str(uuid.uuid4())


    base64_string = request.data.get('raw_video_data')
    base64_thumbnail = request.data.get('raw_thumbnail')
    if base64_string is not None:
        base64_bytes = base64_string.encode('utf-8')
        byte_array = base64.b64decode(base64_bytes)
    # rb - 파일에 쓰기 위한 것     # wb - 파일을 읽기 위한것
        content_uploaddir= "contents/video/"+content_title+".mp4"
        with open('output_from_json.jpg', 'wb') as output_file:
            output_file.write(byte_array)
        with open('output_from_json.jpg', 'rb') as output_file:
            s3.upload_fileobj(output_file, bucket_name, content_uploaddir)
        # s3_url = f'https://kr.object.ncloudstorage.com/{bucket_name}/{content_title}'
        s3_url = f'https://kr.object.ncloudstorage.com/{bucket_name}/contents/video/{content_title}'

        if base64_thumbnail is not None:
            base64_bytes_thumb = base64_thumbnail.encode('utf-8')
            byte_array_thumb = base64.b64decode(base64_bytes_thumb)        
            content_uploaddir_thumb= "contents/thumbnail/"+content_title+".png"
            with open('output_thumnail_json.png', 'wb') as output_file:
                output_file.write(byte_array_thumb)
            with open('output_thumnail_json.png', 'rb') as output_file:
                print(output_file)
                s3.upload_fileobj(output_file, bucket_name, content_uploaddir_thumb)

            # s3_thumbnail_url = f'https://kr.object.ncloudstorage.com/{bucket_name}/{content_title}'

        try:
            content_insert = f''' insert into au_ugccontent (content_id, content_title, child_id, user_id, child_name, content_upload_date, content_s3_url) VALUES ("{content_id}","{content_title}","{child_id}","{user_id}","{child_name}","{now_asia_seoul}","{s3_url}" ) '''
            content_insert_ql = sql_executer(content_insert)
            json_response = default_result(200,True,'content successfully insertted to table')
            return Response(json_response, status = status.HTTP_200_OK)

        except:
            json_response = default_result(400,False,'content table insert False')
            return Response(json_response, status = '401')


    else:
        json_response = default_result(400,False,'file is not mp4 file')
        return Response(json_response, status = '400')





@csrf_exempt
@token_required
@api_view(["POST"])
def content_list(request):
    body = request.body.decode("utf-8")
    data = json.loads(body)
    content_title = data.get("content_title")

    user_id = data.get("user_id") #해당계정의 user_id
    sort_order = data.get("sort_order")
    content_list = []



# 목록 조회를 할떄마다 presigned url 로 변경

    if sort_order == 'like':
        try:
            content_ql = f''' SELECT content_title ,content_s3_url,like_count,content_upload_date from au_ugccontent au left join au_likecount as al on au.content_id = al.content_id where user_id != "{user_id}" order by like_count desc; '''
            content_tuple = sql_executer(content_ql)
            for record in content_tuple:
                content_title, content_s3_url, like_count,content_upload_date = record
                content_dict = {
                    "content_title": content_title,
                    # create_s3_url
                    "content_s3_url": content_s3_url,
                    "like_count": like_count,
                    "content_upload_date":content_upload_date
                }
                content_list.append(content_dict) # 딕셔너리를 리스트에 추가
            response_data = {
                            "code": 200,
                            "success": True,
                            "message": "success",
                            "data" : {"content_list": content_list}
                            }
            json_response = response_data
            return Response(json_response, status= status.HTTP_200_OK)
        except:
            json_response = default_result(400,False,'content table select False')
            return Response(json_response, status = '401')        
    elif sort_order == 'time':
        try:
            content_ql = f''' SELECT content_title ,content_s3_url,like_count,content_upload_date from au_ugccontent au left join au_likecount as al on au.content_id = al.content_id where user_id != "{user_id}" order by content_upload_date desc; '''
            content_tuple = sql_executer(content_ql)
            for record in content_tuple:
                content_title, content_s3_url, like_count,content_upload_date = record
                content_dict = {
                    "content_title": content_title,
                    "content_s3_url": content_s3_url,
                    "like_count": like_count,
                    "content_upload_date":content_upload_date
                }
                content_list.append(content_dict) # 딕셔너리를 리스트에 추가
            response_data = {
                            "code": 200,
                            "success": True,
                            "message": "success",
                            "data" : {"content_list": content_list}
                            }
            json_response = response_data
            return Response(json_response, status= status.HTTP_200_OK)
        except:
            json_response = default_result(400,False,'content table select False')
            return Response(json_response, status = '401')
    else:
        json_response = default_result(401,False,'check sort_order')
        return Response(json_response, status = '401')
    
# 상세 ㅠㅜ
@csrf_exempt
@token_required
@api_view(["POST"])
def content_detail_list(request):
    now_asia_seoul = cur_time_asia()
    body = request.body.decode("utf-8")
    data = json.loads(body)
    content_title = data.get("content_title")
    content_list = []
    try:
        content_ql = f''' SELECT content_title ,content_s3_url,like_count,content_upload_date from au_ugccontent au left join au_likecount as al on au.content_id = al.content_id where content_title = "{content_title}" order by like_count desc; '''
        content_tuple = sql_executer(content_ql)
        for record in content_tuple:
            content_title, content_s3_url, like_count,content_upload_date = record
            content_dict = {
                "content_title": content_title,
                "content_s3_url": content_s3_url,
                "like_count": like_count,
                "content_upload_date":content_upload_date
            }
            content_list.append(content_dict) # 딕셔너리를 리스트에 추가
        response_data = {
                        "code": 200,
                        "success": True,
                        "message": "success",
                        "data" : {"content_list": content_list}
                        }
        json_response = response_data
        return Response(json_response, status= status.HTTP_200_OK)
    except:
        json_response = default_result(400,False,'content table select False')
        return Response(json_response, status = '401')        


@csrf_exempt
@token_required
@api_view(["POST"])
def content_detail_revise(request):
    now_asia_seoul = cur_time_asia()
    body = request.body.decode("utf-8")
    data = json.loads(body)
    content_id = data.get("content_id")
    child_id = data.get("child_id")
    content_title = data.get("content_title")
    like_yn = data.get("like_yn")
# 좋아요 삽입,
    if like_yn == "Y":
        try:
            content_ql = f''' INSERT INTO au_likecount (content_id, like_count, child_id, update_date , create_date) VALUES ( "{content_id}", 1, "{child_id}","{now_asia_seoul}", "{now_asia_seoul}" ) '''
            content_tuple = sql_executer(content_ql)
            json_response = default_result(200,True,'video like successfully inserted')
            return Response(json_response, status = status.HTTP_200_OK)
        except:
            json_response = default_result(400,False,'already you got like in this video')
            return Response(json_response, status = '401')            
# 좋아요 삭제,
    elif like_yn == "N":
        try:
            content_ql = f''' DELETE from au_likecount where content_id = "{content_id}" and child_id = "{child_id}" '''
            content_tuple = sql_executer(content_ql)

            json_response = default_result(200,True,'video like successfully deleted')
            return Response(json_response, status= status.HTTP_200_OK)
        except:
            json_response = default_result(400,False,'content table delete False')
            return Response(json_response, status = '401')    
    else :
            json_response = default_result(400,False,'content table select False')
            return Response(json_response, status = '401')        

# 
# COU.7.1 #charsi list
@csrf_exempt
@token_required
@api_view(["POST"])
def creativity_charsi_list(request):
    now_asia_seoul = cur_time_asia()
    body = request.body.decode("utf-8")
    data = json.loads(body)
    child_id = data.get("child_id")
    try :
        #child age 
        child_birth_ql = f''' SELECT left(birth_date,10)  from au_child where child_id = "{child_id}"  '''
        birth_date = sql_executer(child_birth_ql)[0][0]

        birth_date_time = datetime.strptime(birth_date, '%Y-%m-%d')
        target_age = now_asia_seoul.year - birth_date_time.year - ((now_asia_seoul.month, now_asia_seoul.day) < (birth_date_time.month, birth_date_time.day))

        # charsili_ql = f''' select distinct level_id ,level_name,level_number from au_charsilevel where target_age = "{target_age}" order by "level_id" asc '''
        charsili_ql = f''' select distinct level_name,level_number from au_charsilevel where target_age = "{target_age}" order by "level_number" asc '''
        charsi_list = sql_executer(charsili_ql)
        char_lists = []

        fin_charql = f''' select max(level_number) from au_creative_behavior where child_id = "{child_id}" '''
        fin_charsirow = sql_executer(fin_charql)
        fin_charsi = fin_charsirow[0][0]
# child aging, target charsi change. 
# finished charsi
        for record in charsi_list:
            # level_id,level_name,level_number = record
            level_name,level_number = record
            char_dict = { 
                "level_name":level_name,
                "level_number":level_number
             }
            char_lists.append(char_dict)

# give me charsi number that child completed.
# in au_creativity behavior, i can find max number of charsi id, and when i coordinate with charsi. 
        response_data = {
                "code": 200,
                "success": True,
                "message": "success",
                "data" : {"char_list": char_lists,
                          "fin_charsi": fin_charsi
                          }
                }
        json_response = response_data
        return Response(json_response, status= status.HTTP_200_OK)
    
    except:
        json_response = default_result(400,False,'charsi table select False')
        return Response(json_response, status = '401')   


@csrf_exempt
@token_required
@api_view(["POST"])
def creativity_file_save(request):
# 대상테이블 # 창의력 활동 
    now_asia_seoul = cur_time_asia()
    body = request.body.decode("utf-8")
    data = json.loads(body)
    user_id = data.get("user_id")
    child_id = data.get("child_id")
    level_num = data.get("level_num")
    level_name = data.get("level_name")
    # base64_mp3 = request.data.get('raw_sound_data')
    # base64_img = request.data.get('raw_img_data')
    base64_mp3 = data.get('raw_sound_data')
    base64_img = data.get('raw_img_data')
# create s3 url 
    try:
        s3 = s3connect()
        bucket_name = 'aurora'
        if base64_mp3 is None and base64_img is not None:
            
            base64_bytes = base64_img.encode('utf-8')
            byte_array = base64.b64decode(base64_bytes)

            content_uploaddir= "creativity/image/"+user_id+"/"+child_id+"/"+level_name+".png"
            with open('output_from_json.png', 'wb') as output_file:
                output_file.write(byte_array)
            with open('output_from_json.png', 'rb') as output_file:
                s3.upload_fileobj(output_file, bucket_name, content_uploaddir)
            s3_img_url = f'https://kr.object.ncloudstorage.com/{bucket_name}/creativity/image/{user_id}/{child_id}/{level_name}.png'
            insert_ql2 = f''' INSERT INTO au_creative_behavior (child_id, level_number, file_name, create_date, creativity_behavior_s3url) VALUES ("{child_id}","{level_num}","{level_name}.png","{now_asia_seoul}","{s3_img_url}") '''
            insert_tuple = sql_executer(insert_ql2)
            # pdb.set_trace()
        elif base64_img is None and base64_mp3 is not None:

            base64_bytes2 = base64_mp3.encode('utf-8')
            byte_array = base64.b64decode(base64_bytes2)

            content_uploaddir= "creativity/sound/"+user_id+"/"+child_id+"/"+level_name+".mp3"
            with open('output_from_json.mp3', 'wb') as output_file:
                output_file.write(byte_array)
            with open('output_from_json.mp3', 'rb') as output_file:
                s3.upload_fileobj(output_file, bucket_name, content_uploaddir)
            s3_mp3_url = f'https://kr.object.ncloudstorage.com/{bucket_name}/creativity/sound/{user_id}/{child_id}/{level_name}.mp3'
            insert_ql1 = f''' INSERT INTO au_creative_behavior (child_id, level_number, file_name, create_date, creativity_behavior_s3url) VALUES ("{child_id}","{level_num}","{level_name}.mp3","{now_asia_seoul}","{s3_mp3_url}") '''
            insert_tuple = sql_executer(insert_ql1)
  
        elif base64_mp3 is not None and base64_img is not None:
            #소리 
            base64_bytes = base64_mp3.encode('utf-8')
            byte_array = base64.b64decode(base64_bytes)

            content_uploaddir= "creativity/sound/"+user_id+"/"+child_id+"/"+level_name+".mp3"
            with open('output_from_json.mp3', 'wb') as output_file:
                output_file.write(byte_array)
            with open('output_from_json.mp3', 'rb') as output_file:
                s3.upload_fileobj(output_file, bucket_name, content_uploaddir)
            s3_mp3_url = f'https://kr.object.ncloudstorage.com/{bucket_name}/creativity/sound/{user_id}/{child_id}/{level_name}.mp3'
            insert_ql1 = f''' INSERT INTO au_creative_behavior (child_id, level_number, file_name, create_date, creativity_behavior_s3url) VALUES ("{child_id}","{level_num}","{level_name}.mp3","{now_asia_seoul}","{s3_mp3_url}") '''
            insert_tuple = sql_executer(insert_ql1)
            # 이미지
            base64_bytes2 = base64_img.encode('utf-8')
            byte_array = base64.b64decode(base64_bytes2)
            content_uploaddir= "creativity/image/"+user_id+"/"+child_id+"/"+level_name+".png"
            with open('output_from_json.png', 'wb') as output_file:
                output_file.write(byte_array)
            with open('output_from_json.png', 'rb') as output_file:
                s3.upload_fileobj(output_file, bucket_name, content_uploaddir)
            s3_img_url = f'https://kr.object.ncloudstorage.com/{bucket_name}/creativity/image/{user_id}/{child_id}/{level_name}.png'
            insert_ql2 = f''' INSERT INTO au_creative_behavior (child_id, level_number, file_name, create_date, creativity_behavior_s3url) VALUES ("{child_id}","{level_num}","{level_name}.png","{now_asia_seoul}","{s3_img_url}") '''
            insert_tuple = sql_executer(insert_ql2)
       
        json_response = default_result(200,True,'creativity behavior response successfully')
        return Response(json_response, status = 200)

    except pymysql.err.OperationalError:
        json_response = default_result(400,False,'DB table insert error ')
        return Response(json_response, status = 400)
    except:
        json_response = default_result(400,False,'s3 upload problem')
        return Response(json_response, status = 400)   

    json_response = default_result(400,False,'content table select False')
    return Response(json_response, status = 400)   