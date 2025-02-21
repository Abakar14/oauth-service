
1- for info from chrome:
http://localhost:8082/.well-known/openid-configuration

2- to have authorization code:
http://localhost:8082/oauth2/authorize?response_type=code&client_id=client&client_secret=secret&redirect_uri=http://localhost:8082/login/oauth2/code/custom&scope=openid

2.1
http://localhost:8082/oauth2/authorize?response_type=code&client_id=client&client_secret=secret&redirect_uri=http://localhost:8082&scope=openid

http://localhost:8082/?code=qe6qRqSeyNzJhyBdMgmb_77y0FvWMdK8BolP2mv7ICstiCyk6W5EKg6JHK5u24ibryIjluCo5OX4t5fNgf5TzCN1IQi1lPcrFL-dQ7qA0k_QRmUo6m9GK_sv_jGgs0Rs&state=3enorpa0otz


curl -X POST -u client:secret -d "grant_type=client_credentials" http://localhost:8082/oauth2/token 

curl -X POST -u client:secret -d "grant_type=password&username=abakar&password=Aba14mah?" http://localhost:8082/oauth2/token