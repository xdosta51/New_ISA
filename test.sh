#!/bin/sh




printf "\033[0mStarting tests:\n"
echo "Testing DNS IPV6 NOERROR for bazos.cz"
output_dig=$(dig @::1 -p 1234 -6 bazos.cz)
itsok=$(echo "$output_dig" | grep "NOERROR")
if [ -z "$itsok" ] ; then
    printf "\033[0;31m Test 1 Failed\n"
else 
    printf "\033[0;32m Test 1 Passed\n"
fi
printf "\033[0m------------------------------\n"
echo "Testing DNS IPV6 NOTIMP for seznam.cz"
output_dig=$(dig @::1 -p 1234 -6 AAAA seznam.cz)

itsok=$(echo "$output_dig" | grep "NOTIMP")

if [ -z "$itsok" ] ; then
    printf "\033[0;31m Test 2 Failed\n"
else 
    printf "\033[0;32m Test 2 Passed\n"
fi
printf "\033[0m------------------------------\n"
echo "Testing DNS IPV4 NOTIMP for seznam.cz"
output_dig=$(dig @127.0.0.1 -p 1234 AAAA seznam.cz)

itsok=$(echo "$output_dig" | grep "NOTIMP")

if [ -z "$itsok" ] ; then
    printf "\033[0;31m Test 3 Failed\n"
else 
    printf "\033[0;32m Test 3 Passed\n"
fi
printf "\033[0m------------------------------\n"
echo "Testing DNS IPV4 NOERROR for aukro.cz"
output_dig=$(dig @127.0.0.1 -p 1234 aukro.cz)

itsok=$(echo "$output_dig" | grep "NOERROR")

if [ -z "$itsok" ] ; then
    printf "\033[0;31m Test 4 Failed\n"
else 
    printf "\033[0;32m Test 4 Passed\n"
fi
printf "\033[0m------------------------------\n"
echo "Testing DNS IPV4 REFUSED for zzznews.ru"
output_dig=$(dig @127.0.0.1 -p 1234 zzznews.ru)

itsok=$(echo "$output_dig" | grep "REFUSED")

if [ -z "$itsok" ] ; then
    printf "\033[0;31m Test 5 Failed\n"
else 
    printf "\033[0;32m Test 5 Passed\n"
fi
printf "\033[0m------------------------------\n"
echo "Testing DNS IPV6 REFUSED for zzznews.ru"
output_dig=$(dig @::1 -p 1234 zzznews.ru)

itsok=$(echo "$output_dig" | grep "REFUSED")

if [ -z "$itsok" ] ; then
    printf "\033[0;31m Test 6 Failed\n"
else 
    printf "\033[0;32m Test 6 Passed\n"
fi
printf "\033[0m------------------------------\n"
echo "Testing DNS IPV6 NOTIMP CNAME for zzznews.ru"
output_dig=$(dig @::1 -p 1234 CNAME zzznews.ru)

itsok=$(echo "$output_dig" | grep "NOTIMP")

if [ -z "$itsok" ] ; then
    printf "\033[0;31m Test 7 Failed\n"
else 
    printf "\033[0;32m Test 7 Passed\n"
fi
printf "\033[0m------------------------------\n"
echo "Testing DNS IPV6 DNAME for zzznews.ru"
output_dig=$(dig @::1 -p 1234 DNAME zzznews.ru)

itsok=$(echo "$output_dig" | grep "NOTIMP")

if [ -z "$itsok" ] ; then
    printf "\033[0;31m Test 8 Failed\n"
else 
    printf "\033[0;32m Test 8 Passed\n"
fi
printf "\033[0m------------------------------\n"
echo "Testing DNS IPV6 KEY for zzznews.ru"
output_dig=$(dig @::1 -p 1234 KEY zzznews.ru)

itsok=$(echo "$output_dig" | grep "NOTIMP")

if [ -z "$itsok" ] ; then
    printf "\033[0;31m Test 9 Failed\n"
else 
    printf "\033[0;32m Test 9 Passed\n"
fi
printf "\033[0m------------------------------\n"
echo "Testing DNS IPV4 NOTIMP MX for zzznews.ru"
output_dig=$(dig @127.0.0.1 -p 1234 MX zzznews.ru)

itsok=$(echo "$output_dig" | grep "NOTIMP")

if [ -z "$itsok" ] ; then
    printf "\033[0;31m Test 10 Failed\n"
else 
    printf "\033[0;32m Test 10 Passed\n"
fi
printf "\033[0m------------------------------\n"
echo "____________konec_testu______________"