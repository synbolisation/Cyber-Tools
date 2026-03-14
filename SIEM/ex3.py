events = [
    {
        'timestamp': '2024-01-05 12:01:33',
        'ip_address': '192.168.1.1',
        'username': 'root',
        'event_type': 'failed_login',
    },
    {
        'timestamp': '2025-03-05 3:02:34',
        'ip_address': '192.168.200.3',
        'username': 'admin',
        'event_type': 'successful_login',
    },
    {
        'timestamp': '2025-05-03 9:22:46',
        'ip_address': '192.168.15.2',
        'username': 'root',
        'event_type': 'failed_login',
    }
]

for event in events:
    for key, value in event.items():
        print(f"{key}: {value}")
    print()