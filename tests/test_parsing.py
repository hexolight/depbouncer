import base64

import pytest

from depbouncer import commands, manifests, versions


def pk(cmd):
    out = []
    for i in commands.parse(cmd, "C:\\proj"):
        if i.problem:
            out.append(("?", i.problem[0]))
        elif i.bare:
            out.append(("bare", i.bare))
        elif i.req_file:
            out.append(("req", i.req_file.replace("\\", "/").split("/")[-1]))
        else:
            out.append((i.eco, i.name, i.spec))
    return out


@pytest.mark.parametrize("cmd,want", [
    ("npm install lodash", [("npm", "lodash", None)]),
    ("npm i -D @types/node@20.1.0 left-pad@^1", [("npm", "@types/node", "20.1.0"), ("npm", "left-pad", "^1")]),
    ("npm isntall chalk", [("npm", "chalk", None)]),
    ("npm install", [("bare", "npm")]),
    ("npm ci", [("bare", "npm")]),
    ("npm run build && npm test", []),
    ("npm install --registry https://x.corp/ foo", [("?", "custom_registry")]),
    ("npx create-react-app my-app", [("npm", "create-react-app", None)]),
    ("npx -y cowsay hi", [("npm", "cowsay", None)]),
    ("npm exec --package=eslint@9 -- eslint .", [("npm", "eslint", "9")]),
    ("npm create vite@latest app", [("npm", "create-vite", "latest")]),
    ("npm init @scope/app", [("npm", "@scope/create-app", None)]),
    ("pnpm add zod", [("npm", "zod", None)]),
    ("pnpm dlx shadcn@latest init", [("npm", "shadcn", "latest")]),
    ("pnpm exec tsc", []),
    ("yarn add react react-dom@18.2.0", [("npm", "react", None), ("npm", "react-dom", "18.2.0")]),
    ("yarn", [("bare", "npm")]),
    ("yarn global add serve", [("npm", "serve", None)]),
    ("bunx prettier .", [("npm", "prettier", None)]),
    ("npm install git+https://github.com/a/b.git", [("?", "non_registry")]),
    ("npm install ./local-dir", [("?", "non_registry")]),
    ("npm install user/repo", [("?", "non_registry")]),
    ("npm i alias@npm:real@1.0.0", [("npm", "real", "1.0.0")]),
    ("pip install requests", [("pypi", "requests", None)]),
    ("pip3 install 'flask>=2,<3' uvicorn[standard]==0.30.0",
     [("pypi", "flask", ">=2,<3"), ("pypi", "uvicorn", "==0.30.0")]),
    ("python -m pip install -U numpy", [("pypi", "numpy", None)]),
    ("py -3.12 -m pip install pandas", [("pypi", "pandas", None)]),
    ("C:\\Python313\\python.exe -m pip install rich", [("pypi", "rich", None)]),
    ("pip install -r requirements.txt", [("req", "requirements.txt")]),
    ("pip install -e .", [("?", "non_registry")]),
    ("pip install --index-url https://corp/simple x", [("?", "custom_registry")]),
    ("pip install https://x/y.whl", [("?", "non_registry")]),
    ("pip list", []),
    ("uv add httpx", [("pypi", "httpx", None)]),
    ("uv pip install pydantic==2.9.0", [("pypi", "pydantic", "==2.9.0")]),
    ("uv sync", [("bare", "pypi")]),
    ("uvx ruff check .", [("pypi", "ruff", None)]),
    ("uv tool install black", [("pypi", "black", None)]),
    ("uv run --with rich script.py", [("pypi", "rich", None)]),
    ("pipx install poetry", [("pypi", "poetry", None)]),
    ("dotnet add package Newtonsoft.Json --version 13.0.3", [("nuget", "Newtonsoft.Json", "13.0.3")]),
    ("dotnet add src/App.csproj package Serilog", [("nuget", "Serilog", None)]),
    ("dotnet package add Dapper --project x.csproj", [("nuget", "Dapper", None)]),
    ("dotnet tool install -g dotnet-ef", [("nuget", "dotnet-ef", None)]),
    ("dotnet restore", [("bare", "nuget")]),
    ("dotnet build", []),
    ("dotnet add package X -s https://corp/nuget", [("?", "custom_registry")]),
    ("nuget install Foo -Version 1.0", [("nuget", "Foo", "1.0")]),
    ("Install-Package Foo.Bar -Version 2.0", [("nuget", "Foo.Bar", "2.0")]),
    ("cd app; npm install axios", [("npm", "axios", None)]),
    ("cmd /c npm i chalk", [("npm", "chalk", None)]),
    ("powershell -Command \"pip install rich\"", [("pypi", "rich", None)]),
    ("bash -lc 'pnpm add zod'", [("npm", "zod", None)]),
    ("& 'C:\\Program Files\\nodejs\\npm.cmd' install express", [("npm", "express", None)]),
    ("env CI=1 npm i foo", [("npm", "foo", None)]),
    ("FOO=1 pip install bar", [("pypi", "bar", None)]),
    ("iex \"npm i evil\"", [("?", "unparsed_install")]),
    ("echo hello", []),
    ("git status", []),
])
def test_commands(cmd, want):
    assert pk(cmd) == want


def test_encoded_powershell():
    enc = base64.b64encode("npm install evilpkg".encode("utf-16-le")).decode()
    assert pk(f"powershell -EncodedCommand {enc}") == [("npm", "evilpkg", None)]


def test_manifest_kinds():
    assert manifests.kind("C:/a/package.json") == "package.json"
    assert manifests.kind("requirements-dev.txt") == "requirements"
    assert manifests.kind("x/pyproject.toml") == "pyproject"
    assert manifests.kind("App.csproj") == "msbuild"
    assert manifests.kind("Directory.Packages.props") == "msbuild"
    assert manifests.kind("README.md") is None


def names(intents):
    return sorted((i.eco or "?", i.name or i.problem[0], i.spec) for i in intents)


def test_package_json_diff_only_new():
    old = '{"dependencies": {"react": "^18.0.0"}, "scripts": {"build": "tsc"}}'
    new = '{"dependencies": {"react": "^18.0.0", "zod": "^3.23.0"}, "devDependencies": {"vitest": "2.1.0"},' \
          ' "scripts": {"build": "tsc -b"}}'
    assert names(manifests.diff("package.json", old, new)) == [("npm", "vitest", "2.1.0"), ("npm", "zod", "^3.23.0")]


def test_package_json_git_dep_ask():
    new = '{"dependencies": {"x": "github:a/b", "y": "workspace:*"}}'
    assert names(manifests.diff("package.json", "{}", new)) == [("?", "non_registry", None)]


def test_requirements_diff():
    old = "requests==2.31.0\n"
    new = "requests==2.32.3\nflask>=3\n--extra-index-url https://corp/simple\n"
    got = names(manifests.diff("requirements.txt", old, new))
    assert ("pypi", "requests", "==2.32.3") in got and ("pypi", "flask", ">=3") in got
    assert ("?", "custom_registry", None) in got


def test_pyproject_diff():
    new = """[project]
dependencies = ["httpx>=0.27", "rich"]
[project.optional-dependencies]
dev = ["pytest==8.3.0"]
[tool.poetry.dependencies]
python = "^3.11"
django = "^5.0"
"""
    got = names(manifests.diff("pyproject.toml", "", new))
    assert got == [("pypi", "django", ">=5.0,<6"),("pypi", "httpx", ">=0.27"), ("pypi", "pytest", "==8.3.0"),
                   ("pypi", "rich", None)]


def test_csproj_diff():
    old = '<Project><ItemGroup><PackageReference Include="Serilog" Version="3.0.0" /></ItemGroup></Project>'
    new = ('<Project><ItemGroup><PackageReference Include="Serilog" Version="3.0.0" />'
           '<PackageReference Include="Dapper"><Version>2.1.35</Version></PackageReference></ItemGroup></Project>')
    assert names(manifests.diff("App.csproj", old, new)) == [("nuget", "Dapper", "2.1.35")]


def test_xml_entities_refused():
    bomb = '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "aaaa">]><Project/>'
    with pytest.raises(manifests.Unparseable):
        manifests.diff("App.csproj", "", bomb)


def test_broken_json_is_unparseable():
    with pytest.raises(manifests.Unparseable):
        manifests.diff("package.json", "{}", "{ not json")


@pytest.mark.parametrize("spec,vs,want", [
    ("^1.2.3", ["1.2.3", "1.9.0", "2.0.0"], "1.9.0"),
    ("^0.2.3", ["0.2.3", "0.2.9", "0.3.0"], "0.2.9"),
    ("~1.2", ["1.2.0", "1.2.7", "1.3.0"], "1.2.7"),
    (">=1.0.0 <1.5.0", ["1.0.0", "1.4.9", "1.5.0"], "1.4.9"),
    ("1.x || 3.x", ["1.1.0", "2.0.0", "3.4.0"], "3.4.0"),
    ("1.0.0 - 1.2.0", ["1.0.0", "1.2.0", "1.3.0"], "1.2.0"),
    ("*", ["1.0.0", "2.0.0-rc.1"], "1.0.0"),
    ("nonsense!!", ["1.0.0"], None),
])
def test_npm_ranges(spec, vs, want):
    assert versions.npm_resolve(spec, vs) == want


def test_pep440():
    vs = ["1.0", "1.4.2", "2.0", "2.1rc1"]
    assert versions.pypi_resolve(">=1.4,<2", vs) == "1.4.2"
    assert versions.pypi_resolve("~=1.0", vs) == "1.4.2"
    assert versions.pypi_resolve("==2.*", vs) == "2.0"
    assert versions.pypi_resolve("!=2.0", vs) == "1.4.2"
