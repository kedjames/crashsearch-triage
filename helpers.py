import hashlib
import json
import os
import pandas as pd
import pygraphviz as pgv


whitelist = ['libdislocator', '__GI_', '__assert_fail', 'libc_','__stack_','libc.so',
        'libasan.so','libc_start_main','_start', '_IO_new_file', 'malloc.c', '_IO_new_fclose',
        '__GI___assert_fail','_assert_fail_base', '__GI_raise', '__GI_abort','__libc_start_main',
        '__assert_fail_base', '_GI___assert_fail','c:',':','??']


def load_json_file(filename):
    print("[+]Collecting info..")
    with open(filename,'r') as json_file:
        vuln_data = json.load(json_file) 
    return vuln_data
                    

def remove_whitelisted(func_list):
    for item in whitelist:
        if item in func_list:
            func_list.remove(item)
            #print(item)
    return func_list


def parse_backtrace(backtrace, do_whitelist=False):
    backtrace = backtrace.split("<-")
    if '' in backtrace : backtrace.remove('')
    backtrace = list(reversed(backtrace))
    if do_whitelist:
        backtrace = remove_whitelisted(backtrace)
    bt_hash = str(hashlib.sha256(" ".join(backtrace).encode()).hexdigest())
    # max_len_dict[bt_hash] = len(back_trace) 
    return  backtrace, bt_hash, len(backtrace)
    
    
def make_path(directory):                      
    # Parent Directory path 
    parent_dir = os.getcwd()                        
    # Path 
    path = os.path.join(parent_dir, directory) 
    # make dir
    if not (os.path.isdir(path)): 
        os.mkdir(path)
        print("sucessfully created directory") 
    return path


def similarity_graph(cve_list,head,out_file):
    graph = pgv.AGraph()  # the similarity graph
    graph.node_attr["style"] = "filled"
    graph.node_attr["shape"] = "circle"
    graph.node_attr["fixedsize"] = "false"
    graph.node_attr["fontcolor"] = "#FFFFFF"
    
    for item in cve_list:
        graph.add_node(item[0],label=item[0].strip())
        if item[0].strip() == head: continue
        sim = float(item[1]*100)
        sim_str = str(sim)+'%'
        graph.add_edge(head, item[0].strip(),label=sim_str)
        # make a star in shades of red
        n = graph.get_node(item[0].strip())
        n.attr["fillcolor"] = 'orange'
    graph.write(out_file+".dot")  # write to simple.dot
    graph.draw(out_file+".png", prog="circo")  # draw to png using circo layout



def build_crash_graph(searched_backtrace, bug_id, df_crashes):
    colors_list = ['blue','red','black','green3','orange','khaki','purple',
                   'yellow1','navy','aquamarine','deeppink1','magenta',
                   'darkviolet','peru','aqua']
    G=pgv.AGraph()
    G=pgv.AGraph(strict=False,directed=True)
    # Add edge for query bug
    searched_backtrace , _ , _ = parse_backtrace(searched_backtrace, do_whitelist=True)
    edges_from_bt = zip(searched_backtrace, searched_backtrace[1::])
    # G.add_edges_from(edges_from_bt,color=colors_list[0],labelfontsize='5.0', label='Q:'+bug_id)
    is_labelled = False
    for item in edges_from_bt:
            itm =" ".join(item)
            if not is_labelled:
                G.add_edge(item,color=colors_list[0],label='Q:'+bug_id)
                is_labelled =True  
            else:
                G.add_edge(item,color=colors_list[0]) 
    count = 1
    for ind in df_crashes.index: 
        if count >= len(colors_list) : count = 1
        matched_backtrace = df_crashes['group'][ind]
        if '' in matched_backtrace : matched_backtrace.remove('')
        # matched_backtrace = list(reversed(matched_backtrace))
        shared_num = df_crashes['num_shared'][ind]
        edges_from_bt = zip(matched_backtrace, matched_backtrace[1::])
        # Add edges
        # G.add_edges_from(edges_from_bt,color=colors_list[count],labelfontsize='5.0', label=str(shared_num))
        # Extra loop just to avoid repeating labels 
        is_labelled = False
        for item in edges_from_bt:
                itm =" ".join(item)
                if not is_labelled:
                    G.add_edge(item,color=colors_list[count],label=f"shared by:{shared_num}")
                    is_labelled =True  
                else:
                    G.add_edge(item,color=colors_list[count])   
                  
        count+=1
    title = bug_id+'-BIDE-Relationship'
    G.graph_attr['label'] = title
    G.node_attr['shape']='oval'
    G.edge_attr['color']='red'
    G.write(title+'.dot')
    G.layout() # default to neatooval
    G.layout(prog='dot') # use dot
    G.draw(title+'.png', format='png')


def get_path_to_line(directory, line):
    if "/" in line:
        line = os.path.basename(line)

    for path, subdirs, files in os.walk(directory):       
        for file_name in files:
            file_to_assess = os.path.join(path, file_name)
            #print(file_name)
            if os.path.isfile(file_to_assess): 
                if file_name.strip() == line.strip().split(":")[0]: return os.path.join(path, line)
    return None


def get_line(file_name):
    # tmp
    if "./" in file_name: 
        file_name = file_name.replace("./","/")
    tmp_line = ''
    num = 0 
    if ":" not in file_name: return
    with open(file_name.split(":")[0].strip()) as fp: 
        if ".c"in file_name: 
            num = file_name.split(".c:")[1].strip()
            if ':' in num:
                num = num .split(':')[0]
            num = int(num)
        else: 
            num = file_name.split(".h:")[1].strip()
            if ':' in num:
                num = num .split(':')[0]
            num = int(num)
        count=1
        for line in fp: 
            if count == num:
                #return line
                if ";" in line:
                    if ";" in tmp_line:
                        return tmp_line+line
                    else:
                        return tmp_line+line
                else:
                    tmp_line+=line
                    num = count+1
                    #print(num)
            count+=1
            

def get_line_cfg(crash_file,bug_details):
    cve_list = []
    prog_dir = ''
    line_list_dict = dict()
    df_bug_details = pd.read_csv(bug_details)
    df_crashes = pd.read_csv(crash_file)
   
    for ind in df_bug_details.index: 
        dir_list = os.listdir(df_bug_details['location'][ind].strip())
        print(df_bug_details['version'][ind].strip())
        if df_bug_details['version_type'][ind].strip() != 'git':
            for the_dir in dir_list:
                #print('----'the_dir)
                if df_bug_details['version'][ind].strip() in the_dir:
                    prog_dir =  os.path.join(df_bug_details['location'][ind].strip(),\
                        the_dir)
                    #print(prog_dir)
                    break
        else:
            prog_dir = df_bug_details['location'][ind].strip()
            subprocess.Popen("cd "+prog_dir,shell=True,stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            subprocess.Popen("git checkout -f "+df_bug_details['version'][ind].strip(),\
                shell=True,stdout=subprocess.PIPE, stderr=subprocess.STDOUT)  
        print(prog_dir)
        for ind_2 in df_crashes.index: 
            cve_list.append(df_bug_details['cve'][ind].strip())
            if df_bug_details['cve'][ind].strip() == \
            df_crashes['cve'][ind_2].strip():
                #print(df_crashes['cve'][ind_2].strip())
                back_trace_func = df_crashes['back_trace_full'][ind_2]
                back_trace_func = back_trace_func.split("<-")
                if '' in back_trace_func : back_trace_func.remove('')
                back_trace_func = list(reversed(back_trace_func))
                back_trace_func = remove_whitelisted(back_trace_func)
                if not back_trace_func: continue
                #print(back_trace_func)
                for func in back_trace_func:
                    if '.c:' in func:  
                       # print(func)                     
                        line = func.split('@')[1].strip()
                        line_path = get_path_to_line(prog_dir,line)
                        if not line_path:
                            line_details = None
                        else:
                            line_details =  get_line(line_path)
                            if line_details:
                                line_details = line_details.replace("\t", "").replace(" ", "").replace("\n","")
                        if df_bug_details['cve'][ind].strip() in line_list_dict:
                            line_list_dict[df_bug_details['cve'][ind].strip()].append(line_details)
                        else:
                            line_list_dict[df_bug_details['cve'][ind].strip()] = [line_details]
                break
    json.dump(line_list_dict, open(bug_details.replace('.csv','.json'),'w'),indent = 4)
    return line_list_dict
    # bide_df = bide_diversity(args.filename,args.program,['CVE-2016-7515', 'CVE-2016-7518'])
    # # print(bide_df)
    #line_list_dict)


