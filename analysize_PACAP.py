# !/usr/bin/python
# -*- coding:utf-8 -*-
import re
import zlib
import cv2
import pdb

from scapy.all import *

# 定义处理图像函数，返回处理的总图像数与人脸图像数
def http_assembler(pacap_file):
    carved_images = 0
    faces_detected = 0

    a = rdpcap(pacap_file)
    sessions = a.sessions()
    for session in sessions:
        http_payload = ""
        for packet in sessions[session]:
            try:
                if packet[TCP].dport == 80 or packet[TCP].sport == 80:
                    http_payload += str(packet[TCP].payload)
            except:
                pass
        #pdb.set_trace()
        headers = get_http_headers(http_payload)
        #pdb.set_trace()
        if headers is None:
            continue
        #pdb.set_trace()
        image, image_type = extract_image(headers, http_payload)

        if image is not None and image_type is not None:
            # 把图像存储下来
            file_name = "%s_pic_carver_%d.%s" % (pacap_file, carved_images, image_type)
            #pdb.set_trace()
            fd = open("%s/%s" % (pictures_directory, file_name), "wb")

            fd.write(image)
            fd.close()

            carved_images += 1
            # 开始人脸检测
            try:
                result = detect_face("%s/%s" % (pictures_directory, file_name), file_name)
                if result is True:
                    faces_detected += 1
            except:
                print "[!!!] Error  in face_detect of http_assembler"
                pass

    return carved_images, faces_detected

# 定义提取http头文件函数
def get_http_headers(http_payload):
    try:
        #pdb.set_trace()
        # 如果为http流量，提取http头
        headers_raw = http_payload[:http_payload.index("\r\n\r\n")+2]
        # 切分http头   ---------------------------------------------------------
        headers = dict(re.findall(r"(?P<name>.*?):(?P<value>.*?)\r\n", headers_raw))

    except:
        print "[!!!] Error is in get_http_headers"
        return None

    if "Content-Type" not in headers:
        return None
    print "Content-Type is : %s" % headers["Content-Type"]
    return headers

# 定义提取http中图像流的函数
def extract_image(headers, http_payload):

    image = None
    image_type = None
    #pdb.set_trace()
    try:
        if "image" in headers['Content-Type']:
            # 获取图像类型和图像数据
            image_type = headers['Content-Type'].split('/')[1]
            # 为什么这么划分
            image = http_payload[http_payload.index('\r\n\r\n')+4:]
            # 如果数据进行了压缩就进行解压
            try:
                if "Content-Encoding" in headers.keys():
                    if headers["Content-Encoding"] == "gzip":
                        image = zlib.decompress(image, 16+zlib.MAX_WBITS)
                    elif headers["Content-Encoding"] == "deflate":
                        image = zlib.compress(image)
            except:
                pass
    except:
        return None, None
    return image, image_type

# 定义处理图像中人脸的函数
# 对opencv不熟悉，此段程序的原理不明白，有图像识别方面的需要会进一步学习。-----------------
def detect_face(path, filename):

    image = cv2.imread(path)
    #pdb.set_trace()
    cascade = cv2.CascadeClassifier("haarcascade_frontalface_alt.xml")
    rects = cascade.detectMultiScale(image, 1.3, 4, cv2.cv.CV_HAAR_SCALE_IMAGE, (20, 20))

    if len(rects) == 0:
        return False

    rects[:, 2:] += rects[:, :2]
    # 对图像中的人脸进行高亮显示处理
    for x1, y1, x2, y2 in rects:
        cv2.rectrangle(img, (x1, y1), (x2, Y2), (127, 255, 0), 2)

    cv2.imwrite("%s/%s-%s" % (faces_directory, pacap_file, file_name), img)
    return True

# 主函数
if __name__ == "__main__":
    # 定义初始变量
    pictures_directory = "/home/ximen/ctlworld/pictures"
    faces_directory = "/home/ximen/ctlworld/faces"
    #pacap_file = "test2.pcapng"
    pacap_file = "ximen.pcapng"
    ##pdb.set_trace()
    carved_images, faces_detected = http_assembler(pacap_file)
    print "Extract: %d images" % carved_images
    print "Detect: %d images" % faces_detected
