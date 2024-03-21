---
title: 'Machine Learning Security Evasion Competition'
date: 2022-09-29T12:12:44+01:00
draft: false
---

This blogpost contains the process and solution which got me 2nd place in the ML Security Evasion Competition sponsored by Adversa AI, CUJO AI, and Robust Intelligence.

## The Phishing Challenge

The challenge I focused on in this competition was their phishing detection evasion challenge. The goal of the challenge was to evade 8 machine learning models designed to detect phishing pages while maintaining the look of the pages pixel perfect.

A submission counted as evasion when a machine learning model deemed the page as a phishing attempt only with 0.10 confidence, a point was assigned for each model evaded. In total there were 10 HTML templates which were the pages to submit, making it a total of 80 points

## Testing Around

During the challenge an API endpoint was exposed where it was possible to submit a HTML template and get detection scores back from all the 8 models. At first I played around with the pages, manual cleaning and modification and seeing how the models would respond.

The first real submission was quite funny, nowhere in the rules was specified the loading of external resources. So my first thought was host the pages on a separate domain and simply iframe the contents to achieve pixel perfection. This iframe technique was giving me perfect scores on all the models so it seemed promising. However I later found out that my submission was invalid as no loading of external resources was allowed 😂

However the iframe concept stuck around as it surprised me how low scores from the models I was receiving .

## Improved Submission

After that experience I thought: "How do I use iframes to load the content, as they receive very low scores, without loading it from an external source?".  It seemed that a few models were very affected by the amount of content in the page and it seemed that going low was a good idea. 

In the end I settled for making my pages look like this:

```html
<body>
	<script>
		var iframe = document.createElement("iframe");
		iframe.id = "application";
		iframe.src="about:blank";
		iframe.onload = function() {
			var domdoc = iframe.contentDocument || iframe.contentWindow.document;
			domdoc.head.innerHTML = "";			
			domdoc.body.innerHTML = '';
		}
		document.body.appendChild(iframe);
	</script>
</body>
```

I was able to clean and minify the original content and load it in the iframe using JavaScript. So I did this automatically for all templates and achieved a pretty good scores (I was actually leading as this point!).

However a lot of my pages did not seem to achieve pixel perfection and that was causing me to lose a lot of points. So I started focusing on that next.

## Pixel Perfection

To detect if a page was pixel perfect to the original I wrote a simple function in Python which would take a screenshot of the forged and original and then compare the hashes of the two:

```py
def imageSimilarity(page):
    # Get real screenshot
    driver.get(realPath+page)
    r = "/tmp/real"+page+".png"
    driver.save_screenshot(r)
    # Get fake screenshot
    driver.get(fakePath+page)
    f = "/tmp/fake"+page+".png"
    driver.save_screenshot(f)
    
    return hashlib.sha256(open(r, "rb").read()).digest() == hashlib.sha256(open(f, "rb").read()).digest()
```

While this was really good to know if pixel perfection was achieved, when it wasn't I did not know how to modify the page so that it would look the same. So I also wrote a function that would visualize the difference between the two to help me adjust the page:

```py
def calc2D(orig, fake):
    # Load images as grayscale
    image1 = cv2.imread(orig, 0)
    image2 = cv2.imread(fake, 0)

    # Calculate the per-element absolute difference between 
    # two arrays or between an array and a scalar
    diff = 255 - cv2.absdiff(image1, image2)
    cv2.imshow('diff', diff)
    cv2.waitKey()
```

This way I was able to visually see where the difference was and adjust the content using CSS. However sometimes this was still enough and I needed an automatic way to do this:

```py
def adjuster(page, upper, lower, step=0.01):
    original = open(page, "rb").read()
    lowest = 10000000000
    d = 0
    for i in range(original.count("&dist&".encode("utf-8"))):
        for i in tqdm(np.arange(upper, lower, step)):
            i = round(i, 3)
            a = original.replace(b'&dist&', str(i).encode("utf-8"), 1)
            open(page, "wb").write(a)
            if imageSimilarity(page):
                print("FOUND!")
                open(page, "wb").write(a)
                exit()
            c = calc("/tmp/real"+page+".png","/tmp/fake"+page+".png" )
            if c < lowest:
                lowest = c
                d = i
                print(d, lowest)
        original = original.replace(b'&dist&', str(d).encode("utf-8"), 1)
    print(d, lowest)
```

Most of the times the issues were related to spacings not matching the original, so this way I was able to tweak the spacings responsible dynamically. This allowed me to achieve pixel perfection on all my pages locally. Unfortunately the challenge server still marked some of them as not perfect, strange but I was not able to get to the bottom of the issue.

## Adding Noise

Right from the start I knew there was a way that I could've added some noise to the pages content to throw off the machine learning models. By finding the tags which were deemed "good" by the models and inserting them with a `{display:none}` style so that they would not impact the visual, I was able to achieve better scores:

```py
def nestedAdder(content, depth=5, amount=20):
    style = "style=\"display:none;\""
    tags = ["div", "iframe", "a", "p"]
    finished = ""
    for i in range(amount):
        frame = tags*depth
        random.shuffle(frame)
        t = ""
        for f in frame:
            t = "<" + f + " " + style + ">" + t + "</" + f + ">"
        finished += t
    
    finished = "<body>\n" + finished
    return content.replace(b'<body>', finished.encode("utf-8"), 1)
```

This was my last addition to my submission which got me a total score of 46, lower than I hoped for due to the pixel perfection problem. However there was one idea that I wish I would've had the time to explore...

## Beating the Models with a Genetic Algorithm

As explained in a Black Hat talk called [Bot vs Bot for Evading Machine Learning Malware Detection](https://www.youtube.com/watch?v=KTfrbvxKQwo), it is possible to use a genetic algorithm to figure out what the models are "blind to" or "like". I really wanted to try this approach but never got to.

The way this approach would work is by using the scores from the models as a reward system, aiming for them to go down. The algorithm would generate  HTML noise to append to the original page, run it through an oracle which in this case would be the pixel perfection function and then submit the modified page to the API to receive the scores. The generations injecting particually good HTML would live on and optimize to acheive the lowest scores possible.

Of course this is big simplification and building this would require a lot of tweaking and testing, but I believe it was nevertheless possible. 