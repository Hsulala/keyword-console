import json
css=open('common.css').read()
adm=open('admin.html').read().replace('/*CSS*/',css)
cli=open('client.html').read().replace('/*CSS*/',css)
srv=open('server.part.ts').read()
out=srv.replace('function page(','function page_unused(') 
out+='\nconst ADMIN_HTML = '+json.dumps(adm,ensure_ascii=False)+';\n'
out+='const CLIENT_HTML = '+json.dumps(cli,ensure_ascii=False)+';\n'
out+='function page(title: string, body: string) { return `<!DOCTYPE html><html lang="zh-Hant"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${title}</title><style>'+css.replace('`','\\`').replace('${','\\${')+'</style></head><body>${body}</body></html>`; }\n'
out+='\nexport default { port: Number(Bun.env.PORT) || 3000, fetch: app.fetch };\n'
open('index.tsx','w').write(out)
print(len(out))
