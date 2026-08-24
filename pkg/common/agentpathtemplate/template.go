package agentpathtemplate

import (
	"bytes"
	"fmt"
	"maps"
	"text/template"

	sprig "github.com/Masterminds/sprig/v3"
)

var funcList = []string{
	"abbrev",
	"abbrevboth",
	"trunc",
	"trim",
	"upper",
	"lower",
	"title",
	"untitle",
	"substr",
	"repeat",
	"trimAll",
	"trimSuffix",
	"trimPrefix",
	"nospace",
	"initials",
	"swapcase",
	"snakecase",
	"camelcase",
	"kebabcase",
	"wrap",
	"wrapWith",
	"contains",
	"hasPrefix",
	"hasSuffix",
	"quote",
	"squote",
	"cat",
	"indent",
	"nindent",
	"replace",
	"plural",
	"sha1sum",
	"sha256sum",
	"adler32sum",
	"toString",
	"seq",
	"splitList",
	"toStrings",
	"join",
	"sortAlpha",
	"default",
	"empty",
	"coalesce",
	"all",
	"any",
	"compact",
	"mustCompact",
	"ternary",
	"base",
	"dir",
	"clean",
	"ext",
	"isAbs",
	"b64enc",
	"b64dec",
	"b32enc",
	"b32dec",
	"tuple",
	"list",
	"dict",
	"get",
	"set",
	"unset",
	"hasKey",
	"pluck",
	"keys",
	"pick",
	"omit",
	"merge",
	"mergeOverwrite",
	"mustMerge",
	"mustMergeOverwrite",
	"values",
	"append",
	"push",
	"mustAppend",
	"mustPush",
	"prepend",
	"mustPrepend",
	"first",
	"mustFirst",
	"rest",
	"mustRest",
	"last",
	"mustLast",
	"initial",
	"mustInitial",
	"reverse",
	"mustReverse",
	"uniq",
	"mustUniq",
	"without",
	"mustWithout",
	"has",
	"mustHas",
	"slice",
	"mustSlice",
	"concat",
	"dig",
	"chunk",
	"mustChunk",
	"uuidv4",
	"fail",
	"regexMatch",
	"mustRegexMatch",
	"regexFindAll",
	"mustRegexFindAll",
	"regexFind",
	"mustRegexFind",
	"regexReplaceAll",
	"mustRegexReplaceAll",
	"regexReplaceAllLiteral",
	"mustRegexReplaceAllLiteral",
	"regexSplit",
	"mustRegexSplit",
	"regexQuoteMeta",
	"urlParse",
	"urlJoin",
}

// jsonFuncAliases maps the functions exposed by JSONFuncMap to the sprig
// functions implementing them. They are not part of the default function set,
// since they are only useful to templates whose output is structured rather
// than a single path.
//
// toJson is implemented by sprig's mustToJson so that a value that cannot be
// encoded surfaces as an execution error rather than rendering nothing. Sprig's
// own toJson swallows that error and its toRawJson panics; neither distinction
// is worth exposing, and their HTML escaping behavior is not observable to a
// caller that decodes the output.
var jsonFuncAliases = map[string]string{
	"toJson": "mustToJson",
}

var ourMap = make(template.FuncMap)

var jsonMap = make(template.FuncMap)

func init() {
	sprigMap := sprig.TxtFuncMap()
	load := func(names []string, into template.FuncMap) {
		for _, f := range names {
			if fn, ok := sprigMap[f]; ok {
				into[f] = fn
			} else {
				panic(fmt.Errorf("missing sprig function %q", f))
			}
		}
	}
	load(funcList, ourMap)

	for name, sprigName := range jsonFuncAliases {
		fn, ok := sprigMap[sprigName]
		if !ok {
			panic(fmt.Errorf("missing sprig function %q", sprigName))
		}
		jsonMap[name] = fn
	}
}

// JSONFuncMap returns the JSON encoding functions, for callers that consume
// structured template output instead of a single path. Pass the result to
// ParseWithFuncs to make them available to a template.
func JSONFuncMap() template.FuncMap {
	funcs := make(template.FuncMap, len(jsonMap))
	maps.Copy(funcs, jsonMap)
	return funcs
}

// Parse parses an agent path template. It changes the behavior for missing
// keys to return an error instead of the default behavior, which renders a
// value that requires percent-encoding to include in a URI, which is against
// the SPIFFE specification.
func Parse(text string) (*Template, error) {
	return ParseWithFuncs(text, nil)
}

// ParseWithFuncs parses a template like Parse, additionally making the given
// functions available to it. Names in extra override the default function set.
func ParseWithFuncs(text string, extra template.FuncMap) (*Template, error) {
	funcs := ourMap
	if len(extra) > 0 {
		funcs = make(template.FuncMap, len(ourMap)+len(extra))
		maps.Copy(funcs, ourMap)
		maps.Copy(funcs, extra)
	}
	tmpl, err := template.New("agent-path").Option("missingkey=error").Funcs(funcs).Parse(text)
	if err != nil {
		return nil, err
	}
	return &Template{tmpl: tmpl}, nil
}

// MustParse parses an agent path template. It changes the behavior for missing
// keys to return an error instead of the default behavior, which renders a
// value that requires percent-encoding to include in a URI, which is against
// the SPIFFE specification. If parsing fails, the function panics.
func MustParse(text string) *Template {
	tmpl, err := Parse(text)
	if err != nil {
		panic(err)
	}
	return tmpl
}

type Template struct {
	tmpl *template.Template
}

func (t *Template) Execute(args any) (string, error) {
	buf := new(bytes.Buffer)
	if err := t.tmpl.Execute(buf, args); err != nil {
		return "", err
	}
	return buf.String(), nil
}
