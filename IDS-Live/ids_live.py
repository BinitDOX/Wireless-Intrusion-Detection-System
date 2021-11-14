import sys, signal, os

def signal_handler(sig, frame):
    print("\n(!) CTRL-C Pressed")
    os.killpg(os.getpgid(proc.pid), signal.SIGTERM)    
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)


import subprocess
import tkinter as tk
import threading
import numpy as np
import pandas as pd
import joblib
import tensorflow as tf
import cv2
from time import sleep
from tensorflow.keras.models import load_model


class App(threading.Thread):
    speed = 1
    predictions = []
    showNormal = True
    packetNum = 0
    procId = 0

    def __init__(self):
        threading.Thread.__init__(self)
        self.start()

    def callback(self):
        print("\n(!) IDS Stopping")
        print("(+) Cleaning threads")
        os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        print("(+) IDS Halted")
        self.root.quit()
        sys.exit(0)

    def run(self):
        self.root = tk.Tk()
        self.root.protocol("WM_DELETE_WINDOW", self.callback)
        self.root.title('Wireless Intrusion Detection System')
        self.root.geometry("870x500") 
        self.root.resizable(0, 0)
        
        
        def changeSpeed():
            try:
                self.speed = int(speed_ent.get())
            except:
                msg = '(-) Provide an integer as prediction speed'
                print(msg)
                log_lb.insert(tk.END, msg)
                log_lb.yview(tk.END)  


        def showNormalToggle():
            self.showNormal = not self.showNormal
            
        def addEntry():
            if len(self.predictions) != 0:
                for p in self.predictions:
                    if app.showNormal or p != 'Normal':
                        msg = '(+) Packet-'+str(self.packetNum)+' = '+str(p)
                        log_lb.insert(tk.END, msg)
                        log_lb.yview(tk.END)  
                        self.packetNum += 1
                self.predictions = []
            self.root.after(1, addEntry)
        
        ivar = tk.IntVar(value=1)
        frame= tk.Frame(self.root, bg= "#3B3B3B")
        scrollbar = tk.Scrollbar(frame)
        log_lb = tk.Listbox(frame, height = 20, width = 80, bg = "#3B3B3B", activestyle = 'dotbox', fg = "white")
        destroy_btn = tk.Button(frame, text='Stop', width=25, command=self.callback, bg="#464342", fg="white")
        normal_cb = tk.Checkbutton(frame, text='Show Normal', bg="#464342", fg="#E0E0E0", selectcolor="#464342", variable=ivar, command=showNormalToggle)
        speed_lbl = tk.Label(frame, text='Prediction Speed', bg="#464342", fg="white")
        speed_ent = tk.Entry(frame, bg="#464342", width=10, fg="white")
        speed_btn = tk.Button(frame, text='Execute', command=changeSpeed, width=8, bg="#464342", fg="white")

        frame.pack(fill='both', expand= True, padx=2, pady=2)
        
        scrollbar.grid(column=1, rowspan=3, sticky="ns")
        log_lb.grid(row=0, column=0, rowspan=3)
        destroy_btn.grid(row=3, column=0, columnspan=4, padx=30, pady=30)
        normal_cb.grid(row=0, column=2, padx=30, pady=30, columnspan=2)
        speed_lbl.grid(row=1, column=2, padx=30, pady=30, columnspan=2)
        speed_ent.grid(row=1, column=2, padx=10, pady=5, rowspan=2)
        speed_btn.grid(row=1, column=3, padx=0, pady=5, rowspan=2)
        scrollbar.config(command=log_lb.yview)

        addEntry()
        self.root.mainloop()
        
        
        

def load_data(file_path, n, rows):
    loaded = False
    while loaded == False:
        try: 
            df = pd.read_csv(file_path, sep='*', skiprows=range(1, n), nrows=rows)
            loaded = True
        except:
            print('(!) WARN: EOF reached, retrying in 3 seconds')
            sleep(3)
    return df

def load_assets():
    std_scaler = joblib.load('scaler_save/scaler.gz')
    with open('scaler_save/columns.txt', 'r') as f:
        std_cols = np.array([line.strip() for line in f])
    with open('encoder_save/columns.txt', 'r') as f:
        enc_cols = np.array([line.strip() for line in f])
    oh_enc = joblib.load('encoder_save/encoder_x.gz')
    with open('data/relevant_columns2.txt', 'r') as f:
        relevant_cols = [line.strip() for line in f]
    with open('data/class_labels.txt', 'r') as f:
        class_labels = np.array([line.strip() for line in f])
    model = load_model('model_save/best_model.h5')
    return (std_scaler, std_cols, oh_enc, enc_cols, relevant_cols, class_labels, model)

def feature_select(df, relevant_cols):
    df = df[relevant_cols]
    return df

def impute_nulls(df):
    null_cols = list(df.columns[df.isna().any()])
    for c in null_cols:
        df[c] = df[c].apply(pd.to_numeric, errors='ignore')
        df[c] = df[c].fillna(value=0)
    return df
                 
def scale_num_features(df, std_scaler, std_cols):
    try:
        df[std_cols] = std_scaler.transform(df[std_cols])
    except: pass
    return df

def encode_cat_features(df, oh_enc, enc_cols):
    array_ohe = oh_enc.transform(df[enc_cols].astype(str))
    df_ohe = pd.DataFrame(array_ohe, index=df.index)
    df_other = df.drop(columns=enc_cols)
    df = pd.concat([df_ohe, df_other], axis=1)
    return df
                 
def make_predictions(df, model):
    preds = np.argmax(model.predict(df), axis=1)
    preds_labels = class_labels[preds]
    with open('data_test/predictions.txt', 'w') as f:
        [f.write(pl+'\n') for pl in preds_labels]
    return preds_labels

def splash_sc():
    cap = cv2.VideoCapture('splash/wd.mp4')
    while(cap.isOpened()):
      ret, frame = cap.read()
      if ret == True:
        frame = cv2.resize(frame, (700, 400))
        cv2.imshow('Intrusion Detection System', frame)
        if cv2.waitKey(25) & 0xFF == ord('q'):
          break
      else: 
        break
    cap.release()
    cv2.destroyAllWindows()

std_scalar, std_cols, oh_enc, enc_cols, relevant_cols, class_labels, model = load_assets()

f = open('data_test/test.csv', "w")
proc = subprocess.Popen(['tshark', '-i', 'wlan0mon', '-T', 'fields', '-e', 'frame.time_epoch', '-e', 'frame.time_delta', '-e', 'frame.time_delta_displayed', '-e', 'frame.time_relative', '-e', 'frame.len', '-e', 'frame.cap_len', '-e', 'radiotap.length', '-e',  'radiotap.present.tsft', '-e', 'radiotap.mactime', '-e', 'radiotap.datarate', '-e', 'radiotap.channel.freq', '-e', 'wlan.fc.type_subtype', '-e', 'wlan.fc.type', '-e', 'wlan.fc.subtype', '-e', 'wlan.fc.ds', '-e', 'wlan.fc.frag', '-e', 'wlan.fc.retry', '-e', 'wlan.fc.pwrmgt', '-e', 'wlan.fc.moredata', '-e', 'wlan.fc.protected', '-e', 'wlan.duration', '-e', 'wlan.frag', '-e', 'wlan.seq', '-E', 'header=y', '-E', 'separator=*'], stdout=f)

splash_sc()
app = App()
app.procId = proc.pid

n = 1
while True:
    df = load_data('data_test/test.csv', n, app.speed)
    if len(df) == 0: continue
    df = feature_select(df, relevant_cols)
    df = scale_num_features(df, std_scalar, std_cols)
    df = encode_cat_features(df, oh_enc, enc_cols) 
    preds = make_predictions(df, model)
    app.predictions = preds
    app.packetNum = n
    for p in preds:
        if app.showNormal or p != 'Normal':
            print('(+) Packet-'+str(n)+' = '+str(p))
        n += 1
    