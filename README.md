cd server-side
cd server
optional(docker-compose build)
docker-compose run 
docker run -d -p 27017:27017 --name mymongodb mongo

cd /server-side/
py deploy.py
py pyshark3.py

send requests from another device with clients specified in /client-side (should be at same LAN interface.)
py attack-client.py
py regular-client.py