"""Read-only presentation choices for the general host workspace."""
def prepare(data):
    inventory = data.get('discovery')
    processes = inventory['data']['processes'] if inventory else []
    data['top_processes'] = sorted(processes, key=lambda row: (row.get('cpu_percent', -1), row.get('memory_bytes', -1)), reverse=True)[:3]
    # Put unhealthy enabled checks first without changing monitoring policy.
    def priority(row):
        return (not row['enabled'], 0 if row['health'] == 'down' else 1 if row['failures'] else 2 if row['health'] != 'healthy' else 3, row['name'].casefold())
    data['overview_checks'] = sorted(data['checks'], key=priority)
    charts = data.get('history', {}).get('charts', [])
    primary = {'cpu_percent','ram_percent','disk_percent','load_1'}
    data['overview_charts'] = [chart for chart in charts if chart['key'] in primary]
    data['additional_charts'] = [chart for chart in charts if chart['key'] not in primary]
    return data
