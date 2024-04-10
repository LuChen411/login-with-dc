from flask import Flask, redirect, request, session, jsonify
import requests
import json

app = Flask(__name__)
app.secret_key = 'lc411'  # 设置 session 的密钥

# Discord 应用的配置
CLIENT_ID = '1119558014211461221'
CLIENT_SECRET = 'mokXP_DO4GUvRYFfaqBcHIomOVsHuCNL'
REDIRECT_URI = 'http://localhost:5000/callback'  # 在 Discord 开发者门户中设置的回调地址

# 认证路由
@app.route('/')
def index():
    # 重定向用户到 Discord 认证页面
    return redirect(f'https://discord.com/api/oauth2/authorize?client_id={CLIENT_ID}&redirect_uri={REDIRECT_URI}&response_type=code&scope=identify+guilds+email')

# 回调路由，处理 Discord 的回调
@app.route('/callback')
def callback():
    # 从回调中获取授权码
    code = request.args.get('code')

    # 交换授权码以获取访问令牌
    token_response = requests.post('https://discord.com/api/oauth2/token', data={
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET,
        'grant_type': 'authorization_code',
        'code': code,
        'redirect_uri': REDIRECT_URI
    })

    # 提取访问令牌
    access_token = token_response.json().get('access_token')

    # 使用访问令牌获取用户信息
    user_response = requests.get('https://discord.com/api/users/@me', headers={
        'Authorization': f'Bearer {access_token}'
    })

    # 提取用户信息
    user_data = user_response.json()
    session["user"] = user_data["id"]

    # 使用访问令牌获取用户所在的服务器列表
    guilds_response = requests.get('https://discord.com/api/users/@me/guilds', headers={
        'Authorization': f'Bearer {access_token}'
    })

    # 提取服务器列表信息
    guilds_data = guilds_response.json()
    admin_guilds = []
    for guild in guilds_data:
        # 检查用户是否为服务器的拥有者或拥有管理员权限
        if guild['owner'] or (guild['permissions'] & 8 == 8):
            admin_guilds.append(guild)

    with open(f'user/{user_data["id"]}.json','w',encoding='utf8') as fil:
        json.dump(user_data,fil,indent=2)
    with open(f'guilds/{user_data["id"]}.json','w',encoding='utf8') as fil:
        json.dump(admin_guilds,fil,indent=2)

    return jsonify(guilds_data)

# 退出登录路由
@app.route('/logout')
def logout():
    # 清除 session 中的用户信息和服务器列表信息
    session.pop('user', None)
    session.pop('guilds', None)
    return 'Logged out successfully'

# 用户信息路由
@app.route('/user')
def user():
    # 检查用户是否登录
    if 'user' not in session:
        return 'You are not logged in.'

    # 返回用户信息
    return jsonify(session['user'])

# 服务器列表路由
@app.route('/guilds')
def guilds():
    # 检查用户是否登录
    if 'guilds' not in session:
        return 'You are not logged in.'

    # 返回用户所在的服务器列表
    return jsonify(session['guilds'])

if __name__ == '__main__':
    app.run(debug=True)
