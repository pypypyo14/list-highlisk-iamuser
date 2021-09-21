# list-highlisk-iamuser

- 万一アクセスキーが漏洩した時に金銭被害が出そうなIAMユーザを抽出するスクリプト

1. 有効なアクセスキーがある
2. MFA設定なし
3. AWS管理ポリシーの AdministratorAccess or PowerUserAccess or IAMFullAccess が付与されている


## how to use

in AWS CloudShell

```
$ git clone https://github.com/pypypyo14/list-highlisk-iamuser.git
$ cd list-highlisk-iamuser
$ python3 list_highlisk_iamuser.py
# 条件に該当するIAMユーザが存在する場合は以下のように表示される
{'username': 'user1', 'is_mfa_active': False, 'is_accesskey_active': True}
{'username': 'user2', 'is_mfa_active': False, 'is_accesskey_active': True}

```