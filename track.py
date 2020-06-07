"""
Usage example : python3 track.py -t last_24_hours --user tristan
"""

import argparse
from msiempy.event import Event, EventManager
import pandas

def parse_args():

    parser = argparse.ArgumentParser(description='Request logs, aggregate, and print it.')
    parser.add_argument('-t', '--timerange', metavar='Time range', help='SIEM time range to analyse. For example LAST_3_DAYS.', default='last_24_hours')
    parser.add_argument('--user', metavar='User to track')
    parser.add_argument('--ip', metavar='IP to track')
    parser.add_argument('--host', metavar='Hostname to track')
    parser.add_argument('--macaddr', metavar='Macaddress to track')

    args = parser.parse_args()
    return args

#MAIN PROGRAM
if __name__ == "__main__":
    args = parse_args()
    #print(args)
    filters=list()

    if args.user: filters.append(('UserIDSrc',args.user))
    if args.ip: filters.append(('SrcIP',args.ip))
    if args.host: filters.append(('HostID',args.host))
    if args.macaddr: filters.append(('SrcMac', args.macaddr))

    if len(filters)==0:
        print('You must specify a filter. One of the arguments --user --ip --host --macaddr is required')
        exit(-1)

    events = EventManager(
            time_range=args.timerange,
            fields=['SrcMac','SrcIP','UserIDSrc','HostID','EventCount'],
            filters=filters)

    events.load_data(delta='2h', max_query_depth=5)

    if len(events)==0: 
        print('No event found, sorry')
        exit(0)

    for e in events:
        del e['IPSIDAlertID']
        del e['LastTime']
        del e['Rule.msg']

    print("Loaded {} events".format(len(events)))

    summary = (pandas.DataFrame(events)
        .rename(columns={
            "Alert.SrcIP": "IP",
            "Alert.SrcMac": "Macaddress",
            "Alert.BIN(4)":"Hostname",
            "Alert.BIN(7)":"Username",
            "Alert.EventCount":"Occurences"})
        .apply(pandas.to_numeric, errors='ignore')
        .fillna('N/A')
        .groupby(['Macaddress','IP','Hostname','Username'])
        .agg({'Occurences':'sum'})
        .reset_index()
        .sort_values(by=['Occurences'], ascending=False) )

    print("Grouped query results:")
    print(summary.to_string(index=False))