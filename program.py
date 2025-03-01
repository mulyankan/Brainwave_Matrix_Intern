 #phising URL checker using python

 #listing the urls
phising_urls = ["revil,ru", "coti.ru", "doubledragon.cn", "ryuk.ru", "spam.com"]

#user being asked to enter the url
url = input("Enter the url: ")

domain = url.split("//")[-1].split("//")[0]

#checking the condition

if domain in phising_urls:
    print("Alert!, the URL is known phising URL.")
else:
    print("The URL doesn't apear to be a phising URL.")
    