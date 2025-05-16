import requests

ACCESS_TOKEN = 'ваш токен'
VERSION = '5.131'


def get_friends(user_id=None):
    """Получить список друзей пользователя"""
    params = {
        'access_token': ACCESS_TOKEN,
        'v': VERSION,
    }
    if user_id:
        params['user_id'] = user_id

    response = requests.get('https://api.vk.com/method/friends.get', params=params)
    data = response.json()

    if 'response' in data:
        friends_count = data['response']['count']
        friends_ids = data['response']['items']

        params = {
            'access_token': ACCESS_TOKEN,
            'v': VERSION,
            'user_ids': ','.join(map(str, friends_ids)),
            'fields': 'first_name,last_name'
        }
        friends_info = requests.get('https://api.vk.com/method/users.get', params=params).json()

        print(f"\nУ пользователя {friends_count} друзей:")
        for friend in friends_info['response']:
            print(f"{friend['first_name']} {friend['last_name']}")
    else:
        print("Ошибка:", data.get('error', {}).get('error_msg', 'ошибка'))


get_friends()


def get_user_info(user_id=None):
    """Получить информацию о пользователе"""
    params = {
        'access_token': ACCESS_TOKEN,
        'v': VERSION,
        'fields': 'city,country,bdate,sex,photo_max_orig'
    }
    if user_id:
        params['user_ids'] = user_id

    response = requests.get('https://api.vk.com/method/users.get', params=params)
    data = response.json()

    if 'response' in data:
        user = data['response'][0]
        print("\nИнформация о пользователе:")
        print(f"Имя: {user['first_name']} {user['last_name']}")
        print(f"Дата рождения: {user.get('bdate', 'не указана')}")
        print(f"Пол: {'Мужской' if user.get('sex') == 2 else 'Женский' if user.get('sex') == 1 else 'Не указан'}")
        print(f"Страна: {user.get('country', {}).get('title', 'не указана')}")
        print(f"Город: {user.get('city', {}).get('title', 'не указан')}")
        print(f"Фото: {user.get('photo_max_orig', 'нет фото')}")
    else:
        print("Ошибка:", data.get('error', {}).get('error_msg', 'ошибка'))


get_user_info()
get_user_info('shumkov_vadim')


def get_last_posts(user_id=None, count=5):
    """Получить последние посты со стены"""
    params = {
        'access_token': ACCESS_TOKEN,
        'v': VERSION,
        'count': count,
        'filter': 'owner'
    }
    if user_id:
        params['owner_id'] = user_id

    response = requests.get('https://api.vk.com/method/wall.get', params=params)
    data = response.json()

    if 'response' in data:
        posts = data['response']['items']
        print(f"\nПоследние {len(posts)} постов пользователя:")
        for post in posts:
            text = post.get('text', 'Нет текста')[:100] + "..." if len(post.get('text', '')) > 100 else post.get('text',
                                                                                                                 'Нет текста')
            print(f"{post['date']} | ❤️ {post.get('likes', {}).get('count', 0)} | Текст: {text}")
    else:
        print("Ошибка:", data.get('error', {}).get('error_msg'))


get_last_posts(count=3)
get_last_posts('shumkov_vadim', count=3)


def get_groups(user_id=None):
    """Получить список групп/сообществ пользователя"""
    params = {
        'access_token': ACCESS_TOKEN,
        'v': VERSION,
        'extended': 1,
        'fields': 'name,members_count'
    }
    if user_id:
        params['user_id'] = user_id

    response = requests.get('https://api.vk.com/method/groups.get', params=params)
    data = response.json()

    if 'response' in data:
        groups = data['response']['items']
        print(f"\nУ пользователя {data['response']['count']} групп:")
        for group in groups:
            print(f"{group['name']} (id: {group['id']}, участников: {group.get('members_count', 'N/A')})")
    else:
        print("Ошибка:", data.get('error', {}).get('error_msg'))


get_groups()


def get_mutual_friends(target_id):
    """Получить общих друзей с указанным пользователем"""
    params = {
        'access_token': ACCESS_TOKEN,
        'v': VERSION,
        'target_uid': target_id
    }

    response = requests.get('https://api.vk.com/method/friends.getMutual', params=params)
    data = response.json()

    if 'response' in data:
        common_ids = data['response']
        if not common_ids:
            print(f"Нет общих друзей с пользователем {target_id}")
            return

        users = requests.get('https://api.vk.com/method/users.get', params={
            'access_token': ACCESS_TOKEN,
            'v': VERSION,
            'user_ids': ','.join(map(str, common_ids))
        }).json()

        print(f"\nОбщие друзья с пользователем {target_id}:")
        for user in users['response']:
            print(f"{user['first_name']} {user['last_name']}")
    else:
        print("Ошибка:", data.get('error', {}).get('error_msg'))

get_mutual_friends('192350539')


def get_group_info(group_id):
    """Получить подробную информацию о группе"""
    params = {
        'access_token': ACCESS_TOKEN,
        'v': VERSION,
        'group_id': group_id,
        'fields': 'description,members_count,activity,site'
    }

    response = requests.get('https://api.vk.com/method/groups.getById', params=params)
    data = response.json()

    if 'response' in data:
        group = data['response'][0]
        print(f"\nИнформация о сообществе {group['name']}:")
        print(f"🔹 Участников: {group.get('members_count', 'N/A')}")
        print(f"🔹 Тематика: {group.get('activity', 'не указана')}")
        print(f"🔹 Сайт: {group.get('site', 'не указан')}")
        print(f"🔹 Описание: {group.get('description', 'нет описания')[:200]}...")
    else:
        print("Ошибка:", data.get('error', {}).get('error_msg'))

get_group_info('28905875')


def get_group_members(group_id, count=1000):
    """Получить список участников группы"""
    params = {
        'access_token': ACCESS_TOKEN,
        'v': VERSION,
        'group_id': group_id,
        'count': count,
        'fields': 'city,last_seen'
    }

    response = requests.get('https://api.vk.com/method/groups.getMembers', params=params)
    data = response.json()

    if 'response' in data:
        members = data['response']['items']
        print(f"\nПоследние {len(members)} участников группы {group_id}:")
        for member in members:
            city = member.get('city', {}).get('title', 'не указан')
            print(f"{member['first_name']} {member['last_name']} | Город: {city}")
    else:
        print("Ошибка:", data.get('error', {}).get('error_msg'))

get_group_members('192350539')