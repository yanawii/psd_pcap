#何バイトでもできるが、うまく動かない可能性もあるので注意。
#時間が６０秒を超えるとエラーになる

import sys
import os

def main():
    #読み込みファイル名取得
    if(len(sys.argv)>1):
        filename = sys.argv[1]
    else:
        filename = input('file name:')

    #PSD file読み込み
    fp_r = open(filename,"rb")
    #変数定義
    ct_payload = 0
    head_flg = 0
    head_cnt = 0
    payload_flg = 0
    null_flg = 1
    data = []
    data_all = []
    time_stamp=[]
    time_stamp_all=[]
    d_str_old = ""
    while True:
        d = fp_r.read(1)
        if len(d) == 0:
            break
        else:
            pass
        d_str = '%02x'%ord(d)
        d_int = int('0x'+d_str,16)

        if (null_flg==1) & (d_str_old.find("03")==0):
            null_flg = 0
            head_flg = 14
            head_cnt = head_cnt + 1
        elif (head_flg==1):
            ct_payload = d_int
            head_flg = 0
        elif (head_flg>=4) & (head_flg<=11):
            time_stamp.append(d_str)
            head_flg = head_flg -1
        elif (head_flg > 1):
            head_flg = head_flg -1
        elif (ct_payload > 0):
            data.append(d_str)
            ct_payload = ct_payload - 1
        elif (null_flg == 1):
            pass
        else:
            null_flg = 1
            #dataをまとめる
            data_str =""
            for i in range(0,len(data)):
                data_str = data_str+data[i]
            data_all.append(data)
            data = []
            time_stamp_all.append(time_stamp)
            time_stamp = []
        d_str_old = d_str
    print(len(data_all))
    fp_r.close

    #pcap変換用txt作成
    export_txt(filename.split(".")[0]+".txt",data_all,time_stamp_all)
    #pcap生成
    #os.system("text2pcap -l 195 "+filename.split(".")[0]+".txt "+filename.split(".")[0]+".pcap")
    #os.system("del " + filename.split(".")[0]+".txt")

#Zigbeeデータをpcap変換用txtに出力
def export_txt(filename,data_all,time_stamp_all):
    fp = open(filename,"w")
    for i in range(0,len(data_all)):
        time_stamp_all[i].reverse()
        time_str="".join( time_stamp_all[i])
        time=int("0x"+time_str,0)/32*(10**(-6))
        if int(time/60)>=1:
            time_str=str(int(time/60))+":"+str(round(time-(60*int(time/60)),6))
        else:
            time_str="0:"+str(round(time,6))
        fp.write(time_str+"\n")
        cnt=0
        for j in range(0,len(data_all[i])):
            if ((j%16)==0):
                fp.write("%03x"%(cnt)+"0"+" "+data_all[i][j])
                cnt=cnt+1
            elif ((j%16)==15):
                fp.write(" "+data_all[i][j]+"\n")
            else:
                fp.write(" "+data_all[i][j])
        fp.write("\n")
    fp.close

if __name__ == '__main__':
    main()