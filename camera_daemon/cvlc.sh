cvlc -vvv v4l2:///dev/video0:width=640:height=480:fps=30 --sout-x264-preset ultrafast --sout-x264-tune film --sout-transcode-threads 8 --no-sout-x264-interlaced --sout-x264-keyint -1 --sout-x264-lookahead 60 --no-audio --sout-x264-vbv-maxrate 6000 --sout-x264-weightb --sout-x264-weightp=0 --sout-x264-vbv-bufsize 6000 --sout '#transcode{vcodec=h264,vb=2000}:rtp{dst=127.0.0.1,port=10011,sdp=file:///home/user/test.sdp}' &
