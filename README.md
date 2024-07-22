# Direct-Python (mod_dp)
A simple tool to execute Python code embedded within HTML files (imagine PHP).

----
### Features

- [x] Execute Python code within HTML files.
- [x] Keeps same memory across all python blocks.
- [x] Can acccess GET & POST params
- [ ] Maintaining sessions across pages [Work in progress]
- [ ] Setting Mime type of the page [Work in progress]

----
### Prerequisite
1. Apache httpd server
2. Python3

### Install
```
sudo add-apt-repository ppa:deebash/direct-python
sudo apt-get update
sudo apt-get install direct-python
```

----
**Example usage**

Write the below content in a file and save it with extension .dp (Direct-Python)

**hello.dp**
```
<!DOCTYPE html>
<html>
    <head>
        <title>Python Test</title>
    </head>
    <body>
<?dp 
print('<p>Hello World</p>')
a = "~DP_GET['name']"  # using double quotes accepts string
# count = ~DP_GET['total'] to get integer
# userId = ~DP_POST['userId'] to get POST params
?>
<hr>
<p>Hello!
<?dp 
print(a)
?>
</p>
    </body>
</html>

```
:warning: **While embedding python code be aware of indents.**

Just like PHP, you need to use dp after the question mark. Save the file in your root /var/www/html and access it through localhost/hello.dp

----

#### Feedback
Write your feedback to deebash2009@gmail.com
Author: Deebash Dharmalingam (deebash.org)