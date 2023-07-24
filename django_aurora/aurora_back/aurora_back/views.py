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

# strptime 때문에 import . -- strptime 처리방법 ? => create child check 방법.
# from datetime import datetime
from datetime import datetime, timedelta

import os
import sys
import uuid


from aurora_back import settings as aurora_backSettings
sys.path.append(os.path.dirname(aurora_backSettings.__file__))
# Create your views here.



import pymysql
pymysql.install_as_MySQLdb()
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.hashers import make_password
from django.contrib.auth.hashers import check_password
# 해시 비밀번호 점검 import
# 해시 비밀번호 생성 

# aws boto3 툴 import
import boto3
# 랜덤 id 생성
import random
import string


def awsfunction():
    service_name = 's3'
    endpoint_url = 'https://kr.object.ncloudstorage.com'
    region_name = 'kr-standard'
    access_key = '5D04FF07E7BB8C1EFD85'
    secret_key = '0A1DF6FCAA172400D15C650C0E8F1892803C6F71'
    aws_dict = {}
    return print('aws')

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

def sql_excuter_commit(sql_text):

    dbname = "aurora_db"    
    hostip = "db-h4fhm-kr.vpc-pub-cdb.ntruss.com"
    hostport = "3306"
    usrname = "auroraroot"
    usrpw = "auroraroot!2"

    #set db env
    con = pymysql.connect(host=hostip, user=usrname, password=usrpw,db=dbname, charset='utf8') # 한글처리 (charset = 'utf8')
    #set db cusor
    cur = con.cursor()
    #excute sql
    cur.execute(sql_text)

    # 데이타 Fetch
    rows = cur.fetchall()
    con.commit()
    # DB close
    con.close()
    return rows

def generate_token(user_id):
    # 토큰의 만료 시간 설정
    asia_seoul = pytz.timezone('Asia/Seoul')
    # now_asia_seoul = datetime.datetime.now(asia_seoul)
    now_asia_seoul = datetime.now(asia_seoul)
    now_asia_seoul = cur_time_asia()
    # expiration_time = now_asia_seoul + datetime.timedelta(hours=12)
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
        # 토큰의 유효성 검증
        decode_token = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        # return decode_token
        return token
    except jwt.ExpiredSignatureError:
        return 'token expired'
    except jwt.InvalidTokenError:
        return False



@csrf_exempt
@api_view(["POST"])
def login(request):
    if request.method == "POST":

        body = request.body.decode("utf-8")
        data = json.loads(body)
        user_id = data.get("user_id")
        user_pwd = data.get("user_pwd")


        user_check = f''' select user_pwd from au_user where user_id = "{user_id}" '''
        user = sql_excuter_commit(user_check)

        user_typeql = f''' select user_type from au_user where user_id = "{user_id}" '''
        userql = sql_excuter_commit(user_typeql)
        user_type = userql[0][0]
        
        if len(user)>0:
            # user_pwd(사용자 전달 pwd), user_hash_pwd (유저id_에 맞는 pwd 체크)
            user_hashed_pwd = user[0][0]
            hash_chk = hash_pwd_chk(user_pwd,user_hashed_pwd)

            SECRET_KEY = 'aurora_secret_key'
            token = generate_token(user_id)
            token = verify_token(token)

            # 토큰 분기 - 만료이거나, 옳지 않을때, 
            # 토큰 만료 if token == 'token expired'
            # 토큰 (옳지 않은) if token == False 
            # 나머지 옳은 로그인으로 칩니다.
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
                # 왜 비밀번호가 일치하지 않는지 확인필요. + 비밀번호가 일치하지 않을때, success 를 False 로 전달확인 필요.
                # hash_chk == 'success/false'

                # 만약 hash_chk가 false 라면, success 라면 json_response 분기치기. 
                if hash_chk == 'false':
                    response_data = {
                    'success': False,
                    'message': 'pwd False',
                    'user_hashed_pwd': user_hashed_pwd 
                    }
                    json_response = response_data
                    return Response(json_response, status = 403)
                else:
                    asia_seoul = pytz.timezone('Asia/Seoul')
                    # now_asia_seoul = datetime.datetime.now(asia_seoul)
                    now_asia_seoul = datetime.now(asia_seoul)
                    response_data = {
                        'code' : 200,
                        'success': True,
                        'message': 'login succeed',
                        'data' : {'user_token': token,
                        'user_type': user_type,
                        'pwd_check': hash_chk}
                        }
                    update_loginql = f''' UPDATE au_user set login_date = "{now_asia_seoul}" where user_id = "{user_id}" '''
                    updateql = sql_excuter_commit(update_loginql)
                    json_response = response_data
                    return Response(json_response, status = status.HTTP_200_OK)
        else:
            return JsonResponse({
                'success': False,
                'error': 'Invalid login credentials',
                'user_type' : user_type
                }, 
                status=401)


@csrf_exempt
@api_view(["POST"])
def signup(request):

    asia_seoul = pytz.timezone('Asia/Seoul')
    # now_asia_seoul = datetime.datetime.now(asia_seoul)
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
            insertql = sql_excuter_commit(user_insert_ql)
            
            for agreement in user_agreement:
                agreement_num = agreement.get("agreement_num")
                agreement_ver = agreement.get("agreement_ver")
                agreement_yn = agreement.get("agreement_yn")
                agreement_type = agreement.get("agreement_type")
                agreeinsert = f'''  INSERT INTO au_agreements (user_id, agreement_type ,agreement_yn,agreement_num, agreement_ver ,  agreedttm) VALUES ("{user_id}", "{agreement_type}", "{agreement_yn}", "{agreement_num}","{agreement_ver}","{now_asia_seoul}") '''
                insertql = sql_excuter_commit(agreeinsert)
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
            insertql = sql_excuter_commit(user_insert_ql)
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
            #return JsonResponse({
            #    'error': 'invalid evaluator insert ql'},
                status=401)

    elif user_type == "admin":
        user_email = data.get("user_email")
        user_name = data.get("user_name")
        user_pwd = "1111"

# aurora_backend 9
        user_pwd = hash_pwd_mk(user_pwd)
# aurora_backend 9
        try:
            user_insert_ql = f'''  INSERT INTO au_user (user_id, user_pwd, user_type, user_phone,user_email,user_name) VALUES ("{user_id}", "{user_pwd}", "{user_type}", "{user_phone}","{user_email}","{user_name}") '''
            insertql = sql_excuter_commit(user_insert_ql)

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

    return JsonResponse({'error': 'invalid user_type ql'},status=401)


@csrf_exempt
@api_view(["POST"])
def password_reset(request):
    asia_seoul = pytz.timezone('Asia/Seoul')
    now_asia_seoul = datetime.now(asia_seoul)

    body = request.body.decode("utf-8")
    data = json.loads(body)
    user_id = data.get("user_id")
    user_type = data.get("user_type")

    user_typeql = f''' select user_type from au_user where user_id = "{user_id}" '''
    userql = sql_executer(user_typeql)

    # user_type_chk = userql[0][0]
    # try except 문으로 바꾸기. 혹은
    # if user_type == user_type_chk:
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
@api_view(["POST"])
def password_change(request):
    asia_seoul = pytz.timezone('Asia/Seoul')
    # now_asia_seoul = datetime.datetime.now(asia_seoul)
    now_asia_seoul = cur_time_asia()

    body = request.body.decode("utf-8")
    data = json.loads(body)
    user_id = data.get("user_id")
    user_type = data.get("user_type")
    user_cur_pwd = data.get("user_cur_pwd")
    user_new_pwd = data.get("user_new_pwd")

    user_check = f''' select user_pwd from au_user where user_id = "{user_id}" '''
    user_check_col = sql_executer(user_check)
    if len(user_check_col)>0:
        cur_pwd = user_check_col[0][0] #저장된 해시 비밀번호를 불러오기. - 회원가입떄 비번은 해시되서 저장됩니다. 
        # hashed_cur_pwd = hash_pwd_mk(cur_pwd) - 저장된 DB비번을 해시상태로 만들필요는 있다 ?(x) 없다(o)
        # hash_chk = hash_pwd_chk(cur_pwd,hashed_cur_pwd)


        hash_chk = hash_pwd_chk(user_cur_pwd,cur_pwd)         # 그냥패스워드랑 해시 패스워드(DB) 비교해야되는데, 이미 해시 패스워드를 저장합니다. 
        if hash_chk == 'success':
            user_new_pwd = hash_pwd_mk(user_new_pwd)
            update_resetql = f''' UPDATE au_user set user_pwd = "{user_new_pwd}" where user_id = "{user_id}" '''
            updateql = sql_executer(update_resetql)
        else:
            # json_response = default_result('401', 'false', 'matching user does not exist ')
            json_response = default_result( 401,False, 'matching user does not exist ')
            return Response(json_response, status = '401') 

        json_response = default_result(200,True,'password successfully change')
        return Response(json_response, status = status.HTTP_200_OK) 
    else:
        # json_response = default_result('401', 'false', 'matching user does not exist ')
        json_response = default_result(401,False, 'matching user does not exist ')
        return Response(json_response, status = '401') 

@csrf_exempt
@api_view(["POST"])
def delete_user(request):
    asia_seoul = pytz.timezone('Asia/Seoul')
    # now_asia_seoul = datetime.datetime.now(asia_seoul)
    now_asia_seoul = datetime.now(asia_seoul)

    body = request.body.decode("utf-8")
    data = json.loads(body)
    user_id = data.get("user_id")
    user_type = data.get("user_type")

    #유저 존재 확인
    user_check = f''' select user_id from au_user where user_id = "{user_id}" '''
    user_check_col = sql_executer(user_check)
    if len(user_check_col)>0:
        #update sql
        # password update
        delete_useql = f''' Delete from au_user where user_id = "{user_id}" '''
        deleteql = sql_executer(delete_useql)

        # json_response = default_result('200','success','user successfully deleted')
        json_response = default_result(200,True,'user successfully deleted')
        return Response(json_response, status = status.HTTP_200_OK)
    else:
        # json_response = default_result('401', 'false', 'matching user does not exist ')
        json_response = default_result(401,False, 'matching user does not exist ')
        return Response(json_response, status = '401')


@csrf_exempt
@api_view(["POST"])
def admin_list(request):
    asia_seoul = pytz.timezone('Asia/Seoul')
    # now_asia_seoul = datetime.datetime.now(asia_seoul)    
    now_asia_seoul = datetime.now(asia_seoul)    
    body = request.body.decode("utf-8")
    data = json.loads(body)
    # user_id = data.get("user_id")
    # user_name = data.get("user_name")
    user_search = data.get("user_search")
    user_type = data.get("user_type")

    admin_listql = f''' select user_id, user_name, create_date, login_date from au_user where (user_id like "%{user_search}%" or user_name like "%{user_search}%") and user_type = "{user_type}" '''
    admin_list = sql_executer(admin_listql)
    # admin_list = list(admin_list[0])

    response_data = {
                    "success": True,
                    "message": "success",
                    "data" : {"adminlist": admin_list}
                    # "adminlist": "random"
                    }
    # json_response = default_result('200','success','user successfully deleted')
    json_response = response_data
    return Response(json_response, status= status.HTTP_200_OK)
    # 쿼리 튜닝하기 
    # 

@csrf_exempt
@api_view(["POST"])
def admin_create(request):
    asia_seoul = pytz.timezone('Asia/Seoul')
    # now_asia_seoul = datetime.datetime.now(asia_seoul)    
    now_asia_seoul = datetime.now(asia_seoul)    
    body = request.body.decode("utf-8")
    data = json.loads(body)
    user_id = data.get("user_id")
    user_name = data.get("user_name")
    # user_type = data.get("user_type")
    user_phone = data.get("user_phone")
    user_email = data.get("user_email")
# user_id 체크로직 넣기

# back 7
    user_pwd = '123456'
# 해당 패스워드로 해싱 패스워드 생성 
    hashed_pwd = hash_pwd_mk(user_pwd)


# 해싱 패스워드 생성한것을 db 에 저장. -관리자 create 쪽에 해보기 

    try:
        # admin_insert = f''' INSERT INTO au_user (user_id, user_name, user_type, user_phone,user_email,user_pwd) VALUES ("{user_id}","{user_name}" "{user_type}", "{user_phone}","{user_email}", "123456") '''
        # admin_insert = f''' INSERT INTO au_user (user_id, user_name, user_type, user_phone,user_email,user_pwd) VALUES ("{user_id}","{user_name}" ,"admin", "{user_phone}","{user_email}", "123456") '''
        admin_insert = f''' INSERT INTO au_user (user_id, user_name, user_type, user_phone,user_email,user_pwd) VALUES ("{user_id}","{user_name}" ,"admin", "{user_phone}","{user_email}", "{hashed_pwd}") '''
# back 7
        insertql = sql_executer(admin_insert)
        json_response = default_result(200,True, 'admin create success')        
        return Response(json_response, status= status.HTTP_200_OK)

    except:
        # response_data = {
        #             "success": False,
        #             "message": "admin create False"
        #             }        
        # # response_data = default_result('401', 'false', 'admin creation false')
        # json_response = response_data
        json_response = default_result(401,False, 'admin create False')
        return Response(json_response, status = '401')

@csrf_exempt
@api_view(["POST"])
def admin_detail_search(request):
    asia_seoul = pytz.timezone('Asia/Seoul')
    # now_asia_seoul = datetime.datetime.now(asia_seoul)    
    now_asia_seoul = datetime.now(asia_seoul)    
    body = request.body.decode("utf-8")
    data = json.loads(body)
    user_id = data.get("user_id")
    # user_name = data.get("user_name")
    user_type = data.get("user_type")
    try:
        admin_listql = f''' select user_id, user_name, user_email, user_phone from au_user where user_id = "{user_id}"  and user_type = "{user_type}" '''
        admin_list = sql_executer(admin_listql)
        #user_id = admin_list[0][0]
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
        # response_data = {
        #             "code": 401,
        #             "success": False,
        #             "message" : "admin_detail_list get False"
        #             }        
        # response_data = default_result('401', False, 'admin search fail')
        json_response = default_result(401, False, 'admin search fail')
        return Response(json_response, status = '401')
    

@csrf_exempt
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

        # admin_listql = f''' select user_id, user_name, user_email, user_phone from au_user where user_id = "{user_id}"  and user_type = "{user_type}" '''
        # admin_list = sql_executer(admin_listql)
        # admin_detail = admin_list[0]
        # response_data = {
        #             "success": True,
        #             "message" : "user successfully updated"
        #             }
        response_data = default_result(200,True,'user successfully updated')
        json_response = response_data
        return Response(json_response, status= status.HTTP_200_OK)
    except:
        # response_data = {
        #             "success": False,
        #             "message" : "user update fail"
        #             }
        response_data = default_result(401, False, 'user update fail')
        json_response = response_data
        return Response(json_response, status = '401')
    

@csrf_exempt
@api_view(["POST"])
def parent_list(request):
    now_asia_seoul = cur_time_asia()
    body = request.body.decode("utf-8")
    data = json.loads(body)
    user_id = data.get("user_id")

# 기본화면이 리스트가 나와야한다면 ,, 기본에 0 값을 전달해줍니까 ? 


    # user_name = data.get("user_name")
    # user_search = data.get("user_search")
    user_type = data.get("user_type")
    parent_listql = f''' select user_id, user_name, create_date, login_date from au_user where (user_id like "%{user_id}%") and user_type = "{user_type}" '''
    parent_list = sql_executer(parent_listql)

    # response_data = {
    #                 "success": True,
    #                 "message": "user select success",
    #                 "parent_list": parent_list
    #                 }
    
    response_data = {
                    "success": True,
                    "message": "user select success",
                    "data": {"parent_list" : parent_list}
                    }    

    # json_response = default_result('200',True,'user successfully deleted')
    json_response = response_data
    return Response(json_response, status= status.HTTP_200_OK)

@csrf_exempt
@api_view(["POST"])
def parent_detail_search(request):
    now_asia_seoul = cur_time_asia()
    body = request.body.decode("utf-8")
    data = json.loads(body)
    user_id = data.get("user_id")
    # user_name = data.get("user_name")
    # user_search = data.get("user_search")
    user_type = data.get("user_type")

    parent_listql = f''' select user_id, user_name, create_date, login_date from au_user where (user_id like "%{user_id}%") and user_type = "{user_type}" '''
    parent_list = sql_executer(parent_listql)
    # parent_list = list(parent_list[0])

    response_data = {
                    "success": True,
                    "message": "parent detail search success",
                    "data" :{"parent_list": parent_list}
                    }
    # json_response = default_result('200','success','user successfully deleted')
    json_response = response_data
    return Response(json_response, status= status.HTTP_200_OK)


@csrf_exempt
@api_view(["POST"])
def evaluator_list(request):  
    now_asia_seoul = cur_time_asia()
    body = request.body.decode("utf-8")
    data = json.loads(body)
    user_search = data.get("user_search")
    user_approval = data.get("user_approval")     # user_approval ('Y','N')
    # eval_listql = f''' select user_id, user_name, create_date, login_date from au_user where (user_id like "%{user_search}%" or user_name like "%{user_search}%") and user_type = "{user_type}" and user_approval = "{user_approval}" '''
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
@api_view(["POST"])
def evaluator_detail_search(request):  
    now_asia_seoul = cur_time_asia()
    body = request.body.decode("utf-8")
    data = json.loads(body)
    user_id = data.get("user_id")
    # user_name = data.get("user_name")
    try:
        # admin_listql = f''' select user_id, user_name, user_email, user_phone from au_user where user_id = "{user_id}"  and user_type = "{user_type}" '''
        admin_listql = f''' select user_id, user_name, user_email, user_phone from au_user where user_id = "{user_id}" '''
        admin_list = sql_executer(admin_listql)
        #user_id = admin_list[0][0]
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
@api_view(["POST"])
def evaluator_detail_revise(request): 
    now_asia_seoul = cur_time_asia()
    body = request.body.decode("utf-8")
    data = json.loads(body)
    user_id = data.get("user_id")
    # user_type = data.get("user_type")
    user_name = data.get("user_name")
    user_phone = data.get("user_phone")
    user_email = data.get("user_email")
    user_approval = data.get("user_approval")

    try:
        update_ql = f''' UPDATE au_user set user_name = "{user_name}", user_phone = "{user_phone}", user_email = "{user_email}", user_approval = "{user_approval}" where user_id = "{user_id}" '''
        update_ql_com = sql_executer(update_ql)

        # response_data = {
        #             "success": True,
        #             "message" : "user successfully updated"
        #             }
        response_data = default_result(200, True, 'user successfully updated')
        json_response = response_data
        return Response(json_response, status= status.HTTP_200_OK)
    except:
        # response_data = {
        #             "success": False,
        #             "message" : "user update fail"
        #             }
        response_data = default_result(401, False, 'user update fail')
        json_response = response_data
        return Response(json_response, status = '401')

@csrf_exempt
@api_view(["POST"])
def child_list(request):
    now_asia_seoul = cur_time_asia()        
    body = request.body.decode("utf-8")
    data = json.loads(body)
    user_id = data.get("user_id")

    try:
        select_child_ql = f''' select child_name from au_child where user_id = "{user_id}" '''
        child_ql_com = sql_executer(select_child_ql)
        response_data = {
                    "code": 200,
                    "success": True,
                    "message" : "child successfully get",
                    "data" : {                    "child_list" : child_ql_com}
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
@api_view(["POST"])
def child_create(request):
    # asia_seoul = pytz.timezone('Asia/Seoul')
    # # now_asia_seoul = datetime.datetime.now(asia_seoul)    
    # now_asia_seoul = datetime.now(asia_seoul)    
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

            insert_ql = f''' INSERT INTO au_users (child_name, birth_date, child_id, gender, user_id ) VALUES ("{child_name}", '2018-07-07', "{child_id}", "{gender}", "{user_id}"); '''
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
@api_view(["POST"])
def child_detail_search(request):
# 자녀프로필 조회
    # asia_seoul = pytz.timezone('Asia/Seoul')
    # now_asia_seoul = datetime.datetime.now(asia_seoul)    
    now_asia_seoul = cur_time_asia()
    body = request.body.decode("utf-8")
    data = json.loads(body)
    user_id = data.get("user_id")
    child_name = data.get("child_name")
    # user_type = data.get("user_type")

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
@api_view(["POST"])
# 자녀 프로필 수정
def child_detail_revise(request):
    now_asia_seoul = cur_time_asia()
    body = request.body.decode("utf-8")
    data = json.loads(body)
    user_id = data.get("user_id")
    child_name = data.get("child_name")
    gender = data.get("gender")

    try:
        update_ql = f''' UPDATE au_child set child_name = "{child_name}", gender = "{gender}" where user_id = "{user_id}" '''
        update_ql_com = sql_executer(update_ql)

        response_data = default_result(200, True, 'user successfully updated')
        json_response = response_data
        return Response(json_response, status= status.HTTP_200_OK)
    
    except:
        response_data = default_result(401, False, 'user update fail')
        json_response = response_data
        return Response(json_response, status = '401')
    



@csrf_exempt
@api_view(["POST"])
def asset_list(request):
    now_asia_seoul = cur_time_asia()
    body = request.body.decode("utf-8")
    data = json.loads(body)    
    user_id = data.get("user_id")
    # 빈 리스트를 생성합니다.
    asset_list = []
    # 튜플의 값을 설명해주는 딕셔너리로 전환한 후 하나씩 리스트에 추가하는 코드를 만들어주세요
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
                    "success": True,
                    "message": "success",
                    "data" : {"asset_list": asset_list}
                    }

    response_data = default_result(200, True, 'user successfully updated')
    json_response = response_data
    return Response(json_response, status= status.HTTP_200_OK)


@csrf_exempt
@api_view(["POST"])
def delete_asset(request):
    asia_seoul = pytz.timezone('Asia/Seoul')
    now_asia_seoul = datetime.now(asia_seoul)

    body = request.body.decode("utf-8")
    data = json.loads(body)
    user_id = data.get("user_id")
    asset_id = data.get("asset_id")
    asset_apply = data.get("asset_apply")

    #에셋 존재 확인 (db 연동 체크)
    # asset_check = f''' select asset_id from au_asset where asset_id = "{asset_id}" '''
    asset_check = f''' select asset_name from au_asset where asset_id = "{asset_id}" '''
    # 파일이름.
    # 적용중인 에셋 삭제 불가.

    asset_check_col = sql_executer(asset_check)
    if len(asset_check_col)>0:
        try:
            # s3 에셋 삭제 추가하기. 
            service_name = 's3'
            endpoint_url = 'https://kr.object.ncloudstorage.com'
            region_name = 'kr-standard'
            access_key = '5D04FF07E7BB8C1EFD85'
            secret_key = '0A1DF6FCAA172400D15C650C0E8F1892803C6F71'
            s3 = boto3.client(service_name, endpoint_url=endpoint_url, aws_access_key_id=access_key,
                      aws_secret_access_key=secret_key)

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
        # json_response = default_result('401', 'false', 'matching user does not exist ')
        json_response = default_result(401,False, 'matching user does not exist ')
        return Response(json_response, status = '401')

@csrf_exempt
@api_view(["POST"])
def asset_upload(request):
    asia_seoul = pytz.timezone('Asia/Seoul')
    now_asia_seoul = datetime.now(asia_seoul)
    region_name = 'kr-standard'
    s3 = boto3.client('s3', aws_access_key_id='5D04FF07E7BB8C1EFD85',
                  aws_secret_access_key='0A1DF6FCAA172400D15C650C0E8F1892803C6F71', region_name='kr-standard')
    body = request.body.decode("utf-8")
    data = json.loads(body)
    asset_desc = data.get("asset_desc")

    bucket_name = 'aurora'

    if 'zipfile' in request.FILES:
        file = request.FILES['zipfile']
        if file.name.endswith('.zip'):
            bucket_name = 'aurora'
            # file_name_in_s3 = 'application_file/asset/' + file.name
            # 원래는 file.name 을 업로드해야되지만, 에셋 id로 업로드합니다.  
            file_name_in_s3 = 'application_file/asset/' + file.name
            try:
                s3.upload_fileobj(file, 'bucket_name', file_name_in_s3)
            # 업로드, 
                current_time = now_asia_seoul.strftime("%Y%m%d%H%M%S")  # 현재 시간을 문자열로 변환                    
                random_alphabet = ''.join(random.choice(string.ascii_letters) for _ in range(5))  # 랜덤 알파벳 5개 생성
                asset_id = 'A' + current_time + random_alphabet
                # asset_id = str(uuid.uuid4())
                # s3_url = https://kr.object.ncloudstorage.com/your_bucket_name/your_key
                s3_url = f''' https://kr.object.ncloudstorage.com/"{bucket_name}"/"{file_name_in_s3}" '''
            # DB 인서트
                asset_insert = f''' insert into au_assets (asset_id, asset_name,createdttm, asset_desc, aseet_volume, asset_apply, asset_s3_url) VALUES ("{asset_id}", "{file.name}" ,"{now_asia_seoul}", "{asset_desc}", "N", "{s3_url}" ) '''
                asset_insert_ql = sql_executer(asset_insert)
                json_response = default_result(200,True,'asset successfully insertted')
                return Response(json_response, status = status.HTTP_200_OK)
            except:
                json_response = default_result(400,False,'asset insertted False')
                return Response(json_response, status = '401')
    else:
        json_response = default_result(400,False,'file is not zip file')
        return Response(json_response, status = '401') 
# upload s3 url 받기 
# asset_s3_url

@csrf_exempt
@api_view(["POST"])
# 에셋 적용.
def asset_revise(request):
    now_asia_seoul = cur_time_asia()
    body = request.body.decode("utf-8")
    data = json.loads(body)
    asset_id = data.get("asset_id")

    try:
        update_ql = f''' UPDATE au_child set child_name = "{child_name}", gender = "{gender}" where user_id = "{user_id}" '''
        update_ql_com = sql_executer(update_ql)

        # 적용 모두 안함으로 업데이트 
        update_ql = f''' UPDATE au_asset set asset_apply = "N" '''
        update_ql_com = sql_executer(update_ql)

        # 적용 에셋 id 만 적용으로 바뀜.
        update_ql = f''' UPDATE au_asset set asset_apply = "Y" where asset_id = "{asset_id}" '''
        update_ql_com = sql_executer(update_ql)

        response_data = default_result(200, True, 'user successfully updated')
        json_response = response_data
        return Response(json_response, status= status.HTTP_200_OK)
    
    except:
        response_data = default_result(401, False, 'user update fail')
        json_response = response_data
        return Response(json_response, status = '401')