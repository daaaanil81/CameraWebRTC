cvlc v4l2:///dev/video0 --sout-x264-preset slow --sout-x264-tune film --sout-transcode-threads 8 --no-sout-x264-interlaced --sout-x264-keyint 50 --sout-x264-lookahead 100 --sout-x264-vbv-maxrate 6000 --sout-x264-vbv-bufsize 6000 --sout '#transcode{vcodec=h264,vb=6000}:rtp{dst=127.0.0.1,port=9011,mux=ts}'

cvlc -vvv v4l2:///dev/video1:chroma=h264:width=800:height=600 --sout '#rtp{dst=127.0.0.1,port=9011,mux=ts}'

ffmpeg -f v4l2 -video_size 640x480 -i /dev/video0 -an -f rtp -sdp_file video.sdp "rtp://127.0.0.1:9011"

ffmpeg -f v4l2 -i /dev/video2 -an -vcodec libx264 -preset ultrafast -f rtp -sdp_file video.sdp "rtp://127.0.0.1:9011"
