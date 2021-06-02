# GraphQL
## Dump Data
```graphql
{
	allCereals {
		id
		ingredients
		name
	}
}
```

## Change Data
```graphql
mutation {
	updatePlant(plantId:1 , version:1.1, sourceURL: "http://10.10.14.2/")
}

```

## Tools
[graphql/graphql-playground: 🎮 GraphQL IDE for better development workflows (GraphQL Subscriptions, interactive docs & collaboration) (github.com)](https://github.com/graphql/graphql-playground)