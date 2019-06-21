package main

import "net/http"

func serveCSS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/css")
	w.Write([]byte(`
body {background-color: 999999;}
button {
    -webkit-transition-duration: 0.4s; /* Safari */
    transition-duration: 0.4s;
	background-color: #333333;
	background-color: #02bdd9;
	border-radius: 8px;
	border: none;
	color: white;
	padding: 15px 32px;
	text-align: center;
	text-decoration: none;
	display: inline-block;
	float: none;
	font-size: 24px;
	font-weight: bold;
	text-shadow: 1px 1px 1px #000000;
	width: 40%;
}
button:hover {
	background-color: #029db9;
	color: white;
}
.footer {
	position: fixed;
	left: 0;
	bottom: 0;
	height: 40px;
	padding-left: 12px;
	line-height: 40px;
	width: 100%;
	background-color: #333333;
	color: white;
	text-align: left;
}
.error-text{
    font-family: monospace;
    font-size: 24px;
	white-space: pre-wrap;
	hyphens: auto;
	word-break: break-word;
	word-wrap: break-word;
	overflow-wrap: break-word;
}
.header-title {
    font-size: 24px;
}
.header-key {
    font-family: monospace;
    font-size: 24px;
	white-space: pre;
}
.header-value {
    font-family: monospace;
    font-size: 24px;
    white-space: pre-wrap;       /* css-3 */
	hyphens: auto;
	word-break: break-all;
	word-wrap: break-word;
	overflow-wrap: break-word;
}
.header-grid-container {
	display: inline-grid;
	grid-template-columns: min-content auto;
}
.button-grid-container {
	width: 100%;
	display: inline-grid;
	grid-gap: 10px;
}
#success {
	background-color: #bcd819;
}
#error {
	background-color: #e32d31;
	color: white;
}
.card {
    /* Add shadows to create the "card" effect */
    box-shadow: 0 4px 8px 0 rgba(0,0,0,0.2);
    transition: 0.3s;
	width: 100%;
}

/* On mouse-over, add a deeper shadow */
.card:hover {
    box-shadow: 0 8px 16px 0 rgba(0,0,0,0.2);
}

/* Add some padding inside the card container */
.container {
    padding: 2px 16px;
}
`))
}
