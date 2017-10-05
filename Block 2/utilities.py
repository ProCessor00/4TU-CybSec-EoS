import os, re, csv
import datetime, time
import requests
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import matplotlib.font_manager as font_manager
from cycler import cycler
import pylab

def clean(string):
    return string.replace("]","").replace("[","").replace("'","").strip()

# Extracts all honeypot data
def extract_honey(folder):
    honey = []
    num_cols = 7
    print("Extracting honey. This will take a while..")
    files = os.listdir(honey_location)
    print("Total number of files:", len(files))
    for index, filename in enumerate(files):
        if "." not in filename: 
            continue
        print(index, filename)
        with open(honey_location + "/" + filename) as f:
            for row in f:
                row = row.split("$$")
                commands = clean(row[-1])[:300].split(", ")
                login = []
                if len(commands[0]) < 20:
                    login = commands[0:2]
                    commands = commands[2:]
                honey.append(row[:len(row)-1])            
                honey[-1].append(login)          
                honey[-1].append(commands)
                if len(honey[-1]) > 7:
                    num_cols = len(honey[-1])
        print(honey[-1])
    print("Done.")
    return honey, num_cols

def honey_to_panda(honey, cols, small):
    print("Converting honey to panda.. ", end="")
    headers = ["Timestamp", "SrcIP", "SrcPort", "DstIP", "DstPort", "Login", "Commands"]
    if cols > 7:
        headers.append("lol")
    panda = pd.DataFrame(honey, columns=headers)[["Timestamp", "SrcIP", "SrcPort", "DstIP", "Login", "Commands"]]
    panda['Timestamp'] = pd.to_datetime(panda['Timestamp'],format="%Y-%m-%d %H:%M:%S")
    #panda = panda.set_index('Timestamp')
    panda['SrcIP_I'] = panda.apply(lambda row: ip2long(row['SrcIP']), axis=1)
    panda['DstIP_I'] = panda.apply(lambda row: ip2long(row['DstIP']), axis=1)
    panda = panda.sort_values(['Timestamp', 'SrcIP_I', 'DstIP_I'], ascending=[True,True,True])
    panda['Login'] = panda['Login'].apply(lambda x: x.replace("\\\\\\\\", "\\\\")).apply(lambda x: x.replace("\\\\", "\\"))
    panda['Commands'] = panda['Commands'].apply(lambda x: x.replace("\\\\\\\\", "\\\\")).apply(lambda x: x.replace("\\\\", "\\"))
    
    if small:
        panda['Malware'] = panda['Commands'].apply(lambda x: x.find("busybox") > -1)
        panda['Login'] = panda['Login'].apply(lambda x: len(x) == 2 and len(x[1]) == 1)
        del panda['Commands']
        panda = panda[["Timestamp", "SrcIP", "SrcPort", "DstIP", "Login", "Malware", 'SrcIP_I', 'DstIP_I']].reset_index(drop=True)

    print("Done.")
    return panda

# stores all data between the first and the last date (exclusive) in as many parts as there are additional (in between) dates given
def store_panda_date_splitted(path, panda, split_dates):
    print("Storing panda", end="")
    for i in range(len(split_dates) - 1):
        from_date = split_dates[i]
        to_date = split_dates[i + 1]
        panda[(panda['Timestamp'] >= from_date)&(panda['Timestamp'] < to_date)].to_csv(path + "_" + str(i) + ".csv", sep='\t', encoding='utf-8')
        print(".", end="") 
    print(" Done.")   
    
def store_panda(path, panda):
    print("Storing panda.. ", end="")
    panda.to_csv(path + ".csv", sep='\t', encoding='utf-8')
    print(" Done.")
    
def store_one_srcip_panda(panda, srcip):
    print("Storing " + srcip + " panda.. ", end="")
    panda = panda[(panda.SrcIP == srcip)].sort_values(['DstIP_I', 'Timestamp'], ascending=[True,True])
    if not os.path.exists("pandified_per_ip/"):
        os.mkdir("pandified_per_ip/")
    panda.to_csv("pandified_per_ip/pandified_data_"+ srcip + ".csv", sep='\t', encoding='utf-8')
    print("Done.")    

def load_panda(path, num_splits):
    print("Loading panda", end="")
    parts = []
    for i in range(num_splits):
        if num_splits <= 1:
            parts.append(pd.DataFrame.from_csv(path + ".csv", sep='\t', encoding='utf-8'))
        else:
            parts.append(pd.DataFrame.from_csv(path + "_" + str(i) + ".csv", sep='\t', encoding='utf-8'))
        print(".", end="") 
    panda = None
    if num_splits <= 1:
        panda = parts[0]
    else:
        panda = pd.concat(parts)
    panda['Timestamp'] = pd.to_datetime(panda['Timestamp'],format="%Y-%m-%d %H:%M:%S")
    print(" Done.")
    return panda
    
def load_ip_locations(path):
    print("Loading locations.. ", end="")
    ip_locations = pd.DataFrame.from_csv(path + ".csv", sep=',', encoding='utf-8')
    print("Done.")
    return ip_locations
    
def calc_split_dates(panda, num_parts):
    print("Calculating " + str(num_parts) + " split dates", end="")
    split_size = len(panda) / num_parts
    delta_time = datetime.timedelta(hours=8)
    first_date = panda.head(1)['Timestamp'].iloc[0] - delta_time
    last_date = panda.tail(1)['Timestamp'].iloc[0] + delta_time
    split_dates = [first_date]
    curr_first = first_date
    curr_last = first_date + delta_time
    while len(split_dates) < num_parts:# and curr_last < last_date:
        curr_split = panda[(panda['Timestamp'] >= curr_first) & (panda['Timestamp'] < curr_last)]
        if len(curr_split) >= split_size:
            split_dates.append(curr_last)
            curr_first = curr_last        
            print(".", end="")
        curr_last += delta_time
    split_dates.append(last_date)
    print(" Done.")
    print(split_dates)
    return split_dates
   
# gets all publicly available (location) information of an IP.
# NOTE: Do not call this function more than 150 times per minute or we get banned.    
def get_ip_info(srcip):
    url = 'http://ip-api.com/json/' + srcip
    response = requests.get(url)
    return response.json()    

# shows percentage-completed bar    
def perc_write(curr_val, max_val):
    if curr_val % int(max_val / 10) == 0:
        print(round(curr_val / max_val * 10), end="")
        if round(curr_val / max_val * 10) == 10:
            print("")
    elif curr_val % int(max_val / 100) == 0:            
        print("-", end="")

def ip2long(ip):
    return int(ipaddress.ip_address(str(ip)))
    
def long2ip(long):
    return ipaddress.ip_address(long).__str__()    

def get_per_day_data_for_graph(indexed_dataset, all_days, aggregator_column, counter_column):
    isps_dataset = {}
    day_totals = []
    for i, day in enumerate(all_days):
        day_rows = indexed_dataset.loc[[day]]
        day_totals.append(0)
        for index, row in day_rows[[aggregator_column, counter_column]].iterrows():
            amount = row[counter_column] #math.log(row['Amount'], 10)
            if row[aggregator_column] not in isps_dataset:
                if i > 0:
                    isps_dataset[row[aggregator_column]] = [0]*i
                    isps_dataset[row[aggregator_column]].append(amount)
                else:
                    isps_dataset[row[aggregator_column]] = [amount]
            else:
                isps_dataset[row[aggregator_column]].append(amount)
            day_totals[-1] += amount
        for (key, value) in isps_dataset.items():
            if len(value) < i + 1:
                isps_dataset[key].append(0)
                
    # insert empty space in data gap between 31-07 and 29-08    
    blank_insert_index = 31    
    day_totals = day_totals[:blank_insert_index] + [1] + day_totals[blank_insert_index:]
    for (key, value) in isps_dataset.items():
        isps_dataset[key] = value[:blank_insert_index] + [0] + value[blank_insert_index:]
            
    # normalized version for day_total
    isps_dataset_normal = {}
    for (key, value) in isps_dataset.items():
        isps_dataset_normal[key] = [val / day_total * 100 for val,day_total in zip(value, day_totals)]            
        
    return isps_dataset, isps_dataset_normal, day_totals
    
def show_stacked_bar_figure(bar_dict, x_values, width, title, x_axis_label, y_axis_label, savename, max_y, y_step, leg_loc='upper left'):

    pylab.rcParams['figure.figsize'] = (20, 20)
    
    sorted_dataset = sorted(bar_dict.items(), key=lambda x: x[0])

    # Set the font dictionaries (for plot title and axis titles)
    title_font = {'fontname':'Arial', 'size':'22', 'color':'black', 'weight':'normal',
                  'verticalalignment':'bottom'} # Bottom vertical alignment for more space
    axis_font = {'fontname':'Arial', 'size':'18'}

    # Set the font properties (for use in legend)   
    font_path = 'C:\Windows\Fonts\Arial.ttf'
    font_prop = font_manager.FontProperties(fname=font_path, size=14)

    # get colormap
    cmap=plt.cm.spectral
    #cmap=plt.cm.rainbow
    # build cycler with enough equally spaced colors from that colormap
    c = cycler('color', cmap(np.linspace(0.1,1,len(sorted_dataset) + 1)) )
    # supply cycler to the rcParam
    plt.rcParams["axes.prop_cycle"] = c 
    
    bars = np.arange(len(x_values))
    
    values = []
    last_value = None
    for (key, value) in sorted_dataset:
        values.append(plt.bar(bars, value, width, bottom=last_value, edgecolor='black'))
        if last_value:
            last_value = [x + y for x, y in zip(last_value, value.copy())]
        else:
            last_value = value.copy()

    
    if not max_y:
        max_y = max(bar_totals)
        
    plt.title(title, **title_font)            
    plt.xlabel(x_axis_label, **axis_font)
    plt.ylabel(y_axis_label, **axis_font)
    plt.xticks(bars, x_values)
    plt.yticks(np.arange(0, max_y, y_step))
    plt.legend([value[0] for value in values], [first for first,second in sorted_dataset], prop=font_prop, loc=leg_loc, shadow=True)

    if not os.path.exists("metrics_evaluation_figures/"):
        os.mkdir("metrics_evaluation_figures/")
    plt.savefig('metrics_evaluation_figures/' + savename + '.png', dpi=200, bbox_inches='tight')
    plt.show()
