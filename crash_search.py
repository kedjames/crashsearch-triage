import argparse
import operator
import pprint
import time
import os
import mmh3
import pandas as pd
import shelve
import sys
import hashlib
import numpy as np
import pygraphviz as pgv
import json
from networkx.drawing.nx_pydot import write_dot
from prettytable import PrettyTable
from helpers import parse_backtrace, build_crash_graph
from bide_alg import bide_alg


# Crash Search class
class CrashSearch:

    def __init__(self,num_hashes,num_bands,estimated_jaccard_treshold):
        self.num_hashes = num_hashes
        self.num_bands = num_bands
        if self.num_hashes % self.num_bands:
            raise ValueError(f"Incorrect value of {self.num_bands}, "+
                             f"the number of hashes {self.num_hashes} "+
                             "should be divisible by the number of bands")
        self.ngram_size = 2
        curr_path = os.path.dirname(os.path.realpath(__file__))
        self.db_file  = os.path.join(curr_path,"crashes_db")
        self.program = None
        self.search_bug_id = None
        self.estimated_jaccard_treshold = estimated_jaccard_treshold
        self.gt_bug_dict = dict()
        self.search_bug_dict = dict()
        self.jaccard_bug_dict = dict()
        self.cve_to_prog_dict = dict()
        self.cluster_dict = dict()
        self.sim_candidates = []  
        self.time_stopped = 0
        self.time_start = 0   
        self.is_search_op = False 
        self.strict_insert = False        

   
    # Preprocess the CVE files
    def preprocess_crashes(self,filename):
        attribute_list = []
        crash_symptoms = dict()
        df_crashes = pd.read_csv(filename)
                        
        # Filter by program and bug ID when searching
        if self.search_bug_id != None and self.is_search_op:
            df_crashes = df_crashes.loc[df_crashes['bug_id'] == self.search_bug_id] 
        if not len(df_crashes):
            print(f"[+]There are no query crashes matching that id in <{filename}>")
       
        for ind in df_crashes.index: 
            attribute_list.append(df_crashes['crash_func'][ind])
            attribute_list.append(df_crashes['bug_type'][ind])
            attribute_list.append(df_crashes['signal'][ind])
            attribute_list.append(df_crashes['crash_line'][ind])
            back_trace_func = df_crashes['back_trace_func'][ind]
           
            if type(df_crashes['back_trace_func'][ind]) == np.float64: continue
            back_trace_func, _ , _ = parse_backtrace(back_trace_func, do_whitelist=False)
            back_trace_func = [i for i in back_trace_func if i]     
            ngrams = zip(*[back_trace_func[i:] for i in range(self.ngram_size)])
            
            if len(back_trace_func)==1:
                attribute_list.append("".join(back_trace_func[0:]))
            else:
                for ngram in ngrams:
                    attribute_list.append(" ".join(ngram))
            if self.is_search_op:
                crash_symptoms[df_crashes['id'][ind]+'_'+df_crashes['bug_id'][ind]+'_'+str(ind)] = attribute_list
            else:
                crash_symptoms[df_crashes['id'][ind]+'_'+df_crashes['bug_id'][ind]] = attribute_list             
            attribute_list = []
        return crash_symptoms, df_crashes
        
  
    # Deletes database 
    def drop_database(self):    
        if os.path.exists(self.db_file):
            os.remove(self.db_file)
            print(f"[+]The file {self.db_file} was successfully deleted")
        else:
            print(f"[+]The file {self.db_file} does not exist")        

    # Minhash algorithm
    def generate_fingerprint(self, crashes):
        minhash_fingerprint = []
        hashes = []
        for hash_n in range(self.num_hashes):
            for crash in crashes:
                hashes.append(mmh3.hash(crash.encode(),hash_n,signed=False))         
            minhash_fingerprint.append(min(hashes))
            hashes.clear()                
        return minhash_fingerprint

    # LSH algorithm     
    def generate_lsh_index(self, minhash_fingerprint):
        localities = []
        for row_minhash_fp in np.array_split(minhash_fingerprint, self.num_bands):
            index = mmh3.hash(repr(row_minhash_fp),signed=False)
            localities.append(index)
        return localities


    # Save fingerprints to database
    def store_fingerprint(self,filename):        
        bug_db = shelve.open(self.db_file)
        processed_set = set([])
        processed_key = ''
        crash_symptoms, df_crashes = self.preprocess_crashes(filename)
        
        for key, symptom_list in crash_symptoms.items():
            bug_id = str(key.split('_')[1]).strip()
            prog = str(df_crashes.loc[df_crashes.bug_id==bug_id, 'program'].values[0]).strip()
            crash_func = str(df_crashes.loc[df_crashes.bug_id==bug_id, 'crash_func'].values[0]).strip()
            bug_type = str(df_crashes.loc[df_crashes.bug_id==bug_id, 'bug_type'].values[0]).strip()
            signal = str(df_crashes.loc[df_crashes.bug_id==bug_id, 'signal'].values[0]).strip()
            crash_line = str(df_crashes.loc[df_crashes.bug_id==bug_id, 'crash_line'].values[0]).strip()
            back_trace_func = str(df_crashes.loc[df_crashes.bug_id==bug_id, 'back_trace_func'].values[0]).strip()
            minhash_fingerprint = np.array(self.generate_fingerprint(symptom_list))
            fp_hash = mmh3.hash(repr(minhash_fingerprint),signed=False)
            fingerprint_id = str(fp_hash)+"=>"+bug_id
            processed_key = fingerprint_id
            
            if self.strict_insert:
                processed_key = fp_hash
                                
            if processed_key in processed_set: continue
            localities = self.generate_lsh_index(minhash_fingerprint)
            for index in localities:
                index = str(index)                
                if not index in bug_db:
                    bug_db[index] = set([fingerprint_id])
                else:
                    curr_db_items = bug_db[index]
                    curr_db_items.add(fingerprint_id)
                    bug_db[index] = curr_db_items
                bug_db[fingerprint_id] = {'minhashes':minhash_fingerprint,
                           'bug_id': bug_id,
                           'program': prog,
                           'crash_func': crash_func,
                           'bug_type': bug_type,
                           'signal': signal,
                           'crash_line':crash_line,                           
                           'backtrace':back_trace_func
                           }
            processed_set.add(processed_key)
        bug_db.close()
        print(f"[+] inserted {len(processed_set)} unique signatures, of total {len(crash_symptoms.keys())}")

    

    # Search for fingerprints in database
    def search_fingerprint(self,filename):
        bug_db  = shelve.open(self.db_file) 
        bug_trace_set = set([])
        similarity_df_rows = []
        sim_cols = ["searched_bug_id", "searched_program", 
                    "matched_bug_id", "matched_program", "similarity"]
        bide_df_rows = []
        bide_cols = ["searched_bug_id", "searched_program","searched_backtrace",
                     "matched_bug_id", "matched_program","matched_backtrace", "similarity"]  
        bide_dict = dict()      
        search_count = 0 
                     
        crash_symptoms, df_crashes = self.preprocess_crashes(filename)  
       
        for key, symptom_list in crash_symptoms.items():
            search_count+=1
            bug_id = key.split('_')[1]
            search_prog = str(df_crashes.loc[df_crashes.bug_id==bug_id, 'program'].values[0]).strip()
            back_trace_func = str(df_crashes.loc[df_crashes.bug_id==bug_id, 'back_trace_func'].values[0]).strip()
            minhash_fingerprint  = np.array(self.generate_fingerprint(symptom_list))
            fp_hash = mmh3.hash(repr(minhash_fingerprint),signed=False)
            fingerprint_id = str(fp_hash)+"=>"+bug_id
            localities = self.generate_lsh_index(minhash_fingerprint)            
            similar_bug_set = set([])
            for index in localities:
                index = str(index)
                if not index in bug_db:      
                    continue

                for candidate_bug_id in bug_db[index]:
                    locality_minhash_fingerprint = bug_db[candidate_bug_id]['minhashes']          
                    bug_similarity = (locality_minhash_fingerprint == minhash_fingerprint).sum() / float(self.num_hashes)
                    if bug_similarity >= self.estimated_jaccard_treshold:                         
                        similar_bug_set.add((candidate_bug_id,bug_similarity))  
            
            if len(similar_bug_set):
                for item in similar_bug_set:
                    matched_bug_id = item[0].split("=>")[1].strip()
                    sim = item[1]
                    candidate_backtrace = bug_db[item[0]]['backtrace']
                    # Enable if needed 
                    # candidate_bug_type = bug_db[candidate_bug_id]['bug_type']
                    # candidate_signal = bug_db[candidate_bug_id]['signal']
                    # candidate_crash_line = bug_db[candidate_bug_id]['crash_line']
                    # candidate_crash_func = bug_db[candidate_bug_id]['crash_func']   
                    candidate_prog = bug_db[item[0]]['program']
                    row_a = [bug_id, search_prog, matched_bug_id,candidate_prog, sim]
                    row_b = [bug_id, search_prog, back_trace_func, matched_bug_id, 
                             candidate_prog, candidate_backtrace, sim]
                    similarity_df_rows.append(row_a)
                    bide_df_rows.append(row_b)
            else:
                row_a = [bug_id, search_prog, "No Match","No Match","No Match"]  
                similarity_df_rows.append(row_a)            
        if len(similarity_df_rows):
            sim_df = pd.DataFrame(similarity_df_rows, columns=sim_cols)
            bide_df = pd.DataFrame(bide_df_rows, columns=bide_cols)
            table = PrettyTable()
            table.field_names = sim_cols
            table.add_rows(similarity_df_rows)
            print(table.get_string(title=f"Search Results")) 
            # sim_filename = os.path.basename(filename)+"-search-"+str(time.time())+'.csv'
            # bide_filename = os.path.basename(filename)+"-bide-"+str(time.time())+'.csv'  
            sim_filename = os.path.basename(filename.replace(".csv",""))+"-search.csv"
            bide_filename = os.path.basename(filename.replace(".csv",""))+"-bide.csv"      
            sim_df.to_csv(sim_filename, sep=',', encoding='utf-8')
            print(f"[+]Wrote file {sim_filename}")
            bide_df.to_csv(bide_filename, sep=',', encoding='utf-8')
            print(f"[+]Wrote file {bide_filename}")
        bug_db.close()
            

    def process_bt(self, backtrace, seq_id_dict, bide_db, prog_set, trace_len_list, proccess_bug_id):
        backtrace, bt_hash, backtrace_len = parse_backtrace(backtrace, do_whitelist=True)
        trace_len_list.append(backtrace_len)  
        if bt_hash in seq_id_dict:
            seq_id_dict[bt_hash].add(proccess_bug_id)
        else:
            seq_id_dict[bt_hash] = set([proccess_bug_id])      
        bide_db.append(backtrace)
        
                        
    def bide_relationships(self, filename, bug_id):
        seq_id_dict = {}
        trace_len_list = []
        bide_db = []
        df_rows = []
        max_len = 0
        prog_set = set([])   
        bug_list = [] 
        sim_groups = []
        analysis_group = []
        
        df_bide = pd.read_csv(filename)    
        df_bide = df_bide.loc[df_bide['searched_bug_id'] == bug_id.strip()]
        if not len(df_bide):
            print("[+]There are no matching bugs to analyze")
            exit(0)              
        searched_backtrace = df_bide.loc[df_bide.searched_bug_id==bug_id, 'searched_backtrace'].values[0]  
        searched_prog = df_bide.loc[df_bide.searched_bug_id==bug_id, 'searched_program'].values[0]      
        prog_set.add(searched_prog.strip()) 
        bug_list.append(bug_id.strip())
        self.process_bt(searched_backtrace, seq_id_dict, bide_db, prog_set, trace_len_list, bug_id)      
        
        for ind in df_bide.index:
            backtrace = df_bide['matched_backtrace'][ind]
            prog_set.add(df_bide['matched_program'][ind].strip()) 
            proccess_bug_id = df_bide['matched_bug_id'][ind].strip()
            sim = df_bide['similarity'][ind]
            bug_list.append(proccess_bug_id)
            # For json report
            
            sim_groups.append({"bug_id": proccess_bug_id, "similarity": str(sim)})           
            if not backtrace: continue 
            self.process_bt(backtrace, seq_id_dict, bide_db, prog_set, trace_len_list, proccess_bug_id)
        
        max_len = max(trace_len_list)
        bide_curr_db_items = bide_alg(bide_db, 2 , 0, max_len)
        bide_curr_db_items._mine()
        results = bide_curr_db_items._results
        
        for item in results:
            if not item[0]: continue
            row  = [item[0], item[1]-1, len(item[0]) , max_len]
            df_rows.append(row)  
            # For json report
            group_hash = str(hashlib.sha256(" ".join(item[0]).encode()).hexdigest())
            analysis_group.append({"group_id": group_hash[0:8], "bugs": list(set(bug_list)), 
                                   "sequence":item[0], "shared_length": f"{len(item[0])} of {max_len}"})   
        bide_results_df = pd.DataFrame(df_rows, columns=["group", "num_shared", "shared_len" , "max_len"])
        report_file = filename.replace(".csv", "")
        bide_results_df.to_csv(report_file+".csv", sep=',', encoding='utf-8', index=False)
        print(f"[+]Wrote file {report_file+'.csv'}")
        build_crash_graph(searched_backtrace, bug_id, bide_results_df)
        json_report = {"query_id": bug_id, "similarity_groups": sim_groups, "analysis_groups":analysis_group}
        json_report = json.dumps(json_report, indent=4) 
        # Writing to sample.json
        with open(report_file+".json", "w") as outfile:
            outfile.write(json_report)
            print(f"[+]Wrote file {report_file+'.json'}")
        
        
   


# main
 
if __name__ == '__main__':       
    parser = argparse.ArgumentParser(description= "Crash Search System")
    parser.add_argument("-i","--insert",dest="insert",default=None, help="Insert crashes from the specified CSV file")
    parser.add_argument("-s","--search",dest="search",default=None,help="Query a fingerprint from the  specified CSV file")
    parser.add_argument("-d","--drop",dest="drop", action="store_true",default=False,help="Erase datastore")
    parser.add_argument("-r","--rel",dest="relationship", default=None ,help="Use BIDE to Mine Stackbacktraces")
    parser.add_argument("-b","--bug",dest="bug", default=None ,help="Bug ID to search")
    parser.add_argument("-t","--tresh", dest="treshold" ,default=None ,help="Desired MinHash similarity treshold")
    args = parser.parse_args()
    
    # Setup params
    default_tresh = 0.50
    default_bands = 64
    default_hashes = 256
    
    crash_search = CrashSearch(default_hashes,default_bands,default_tresh)    
    if len(sys.argv) == 1:
        parser.print_help()    
    if args.insert:
        crash_search.store_fingerprint(args.insert)            
    if args.search:
        crash_search.is_search_op = True        
        # If a threshold is given
        if args.treshold:
            crash_search.estimated_jaccard_treshold = float(args.treshold)       
        # If a specific Bug_ID is selected  
        if args.bug:
            crash_search.search_bug_id = args.bug.strip()                                  
        crash_search.search_fingerprint(args.search)        
    if args.drop:
        crash_search.drop_database()
    if args.relationship:
        if not args.bug:
            print("Usage: -r <bide_csv_file> -b <bug_id/cve_id>")
            exit(0)
        crash_search.bide_relationships(args.relationship, args.bug)